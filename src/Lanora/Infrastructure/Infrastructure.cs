using System.IO.Compression;
using System.Reflection;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Lanora.Infrastructure;

/// <summary>Per-user application data directory (FR27).</summary>
public sealed class AppPaths
{
    public AppPaths(string? overrideRoot = null)
    {
        Root = overrideRoot ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Lanora");
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Logs);
        Directory.CreateDirectory(Backups);
    }

    public string Root { get; }
    public string Database => Path.Combine(Root, "lanora.db");
    public string Logs => Path.Combine(Root, "logs");
    public string Backups => Path.Combine(Root, "backups");
}

/// <summary>Size-limited, rotating file log. Tokens and secrets are never written.</summary>
public static class AppLog
{
    private const long MaxBytes = 1024 * 1024;
    private const int KeepFiles = 3;
    private static readonly object Gate = new();
    private static string? _dir;

    public static void Init(string dir) => _dir = dir;

    public static void Info(string area, string message) => Write("INFO", area, message);
    public static void Warn(string area, string message) => Write("WARN", area, message);
    public static void Error(string area, Exception ex) => Write("ERROR", area, ex.GetType().Name + ": " + ex.Message + Environment.NewLine + ex.StackTrace);
    public static void Error(string area, string message) => Write("ERROR", area, message);

    private static void Write(string level, string area, string message)
    {
        if (_dir is null) return;
        try
        {
            lock (Gate)
            {
                var file = Path.Combine(_dir, "lanora.log");
                if (File.Exists(file) && new FileInfo(file).Length > MaxBytes) Rotate(file);
                File.AppendAllText(file, $"{DateTimeOffset.Now:O} [{level}] {area}: {message}{Environment.NewLine}");
            }
        }
        catch
        {
            // A failure to write the log does not stop the application.
        }
    }

    private static void Rotate(string file)
    {
        for (var i = KeepFiles - 1; i >= 1; i--)
        {
            var src = file + "." + i;
            var dst = file + "." + (i + 1);
            if (File.Exists(dst)) File.Delete(dst);
            if (File.Exists(src)) File.Move(src, dst);
        }
        File.Move(file, file + ".1");
    }

    public static void DeleteAll()
    {
        if (_dir is null) return;
        lock (Gate)
        {
            foreach (var f in Directory.GetFiles(_dir, "lanora.log*"))
            {
                try { File.Delete(f); } catch { }
            }
        }
    }
}

/// <summary>Resources embedded in the application (web assets and versioned JSON files).</summary>
public static class Res
{
    private static readonly Assembly Asm = typeof(Res).Assembly;

    public static Stream? Open(string logicalName) => Asm.GetManifestResourceStream(logicalName);

    public static string ReadText(string logicalName)
    {
        using var s = Open(logicalName) ?? throw new FileNotFoundException(logicalName);
        Stream input = logicalName.EndsWith(".gz", StringComparison.Ordinal) ? new GZipStream(s, CompressionMode.Decompress) : s;
        using var r = new StreamReader(input, Encoding.UTF8);
        return r.ReadToEnd();
    }

    public static T ReadJson<T>(string logicalName) =>
        JsonSerializer.Deserialize<T>(ReadText(logicalName), Json.Options) ?? throw new InvalidDataException(logicalName);
}

public static class Json
{
    public static readonly JsonSerializerOptions Options = Create();

    private static JsonSerializerOptions Create()
    {
        var o = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DictionaryKeyPolicy = null,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            NumberHandling = JsonNumberHandling.Strict,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip,
        };
        return o;
    }

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
}

public static class Clock
{
    public static DateTimeOffset Now => DateTimeOffset.UtcNow;
    public static string Iso(DateTimeOffset t) => t.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture);
    public static string NowIso() => Iso(Now);
    public static DateTimeOffset Parse(string s) => DateTimeOffset.Parse(s, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal);
}

/// <summary>Limits untrusted text (banners, device names) and strips control characters (SEC05).</summary>
public static class SafeText
{
    public static string? Clean(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return value;
        var sb = new StringBuilder(Math.Min(value.Length, max));
        foreach (var ch in value)
        {
            if (sb.Length >= max) break;
            if (ch == '\t' || ch == ' ') { sb.Append(' '); continue; }
            if (char.IsControl(ch) || ch == '�' || char.IsSurrogate(ch)) continue;
            sb.Append(ch);
        }
        var s = sb.ToString().Trim();
        while (s.Contains("  ", StringComparison.Ordinal)) s = s.Replace("  ", " ", StringComparison.Ordinal);
        return s;
    }

    /// <summary>Converts raw bytes from the network into printable ASCII text.</summary>
    public static string PrintableAscii(ReadOnlySpan<byte> data, int max)
    {
        var sb = new StringBuilder(Math.Min(data.Length, max));
        foreach (var b in data)
        {
            if (sb.Length >= max) break;
            if (b == '\r' || b == '\n' || b == '\t') { if (sb.Length > 0 && sb[^1] != ' ') sb.Append(' '); continue; }
            if (b >= 0x20 && b < 0x7F) sb.Append((char)b);
        }
        return sb.ToString().Trim();
    }
}

/// <summary>API error with a fixed error code, localization key and safe detail. Stack traces never reach the UI.</summary>
public class ApiException(int status, string code, object? details = null) : Exception(code)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
    public object? Details { get; } = details;
}
