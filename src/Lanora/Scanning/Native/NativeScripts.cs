using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using Lanora.Infrastructure;
using Lanora.Net;

namespace Lanora.Scanning.Native;

/// <summary>
/// Native service checks (implemented in C#). Safe detection/information only:
/// http-title, ssh-banner, ftp-anon, ssl-enum. No exploitation; strict time/size limits apply.
/// </summary>
public sealed partial class NativeScripts
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(3);

    [GeneratedRegex(@"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex TitleTag();

    public async Task<List<ScriptEvidence>> RunAsync(uint ip, IEnumerable<int> openTcpPorts, bool includeVuln, CancellationToken ct)
    {
        var scripts = new List<ScriptEvidence>();
        foreach (var port in openTcpPorts)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                if (port is 80 or 8080 or 8000 or 8888 or 5000 or 3000)
                    await HttpTitle(ip, port, scripts, ct).ConfigureAwait(false);
                else if (port is 443 or 8443 or 9443)
                    await SslEnum(ip, port, scripts, ct).ConfigureAwait(false);
                else if (port is 22 or 2222)
                    await SshHostKey(ip, port, scripts, ct).ConfigureAwait(false);
                else if (port is 21 or 2121)
                    await FtpAnon(ip, port, scripts, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException or OperationCanceledException)
            {
                // A failed check does not stop the scan.
            }
        }
        return scripts;
    }

    private static async Task<NetworkStream> ConnectAsync(uint ip, int port, CancellationToken ct)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(Ipv4.ToAddress(ip), port), ct).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose(); // the socket is not leaked if the connection fails
            throw;
        }
    }

    private static async Task HttpTitle(uint ip, int port, List<ScriptEvidence> scripts, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        await using var stream = await ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
        var req = Encoding.ASCII.GetBytes($"GET / HTTP/1.0\r\nHost: {Ipv4.Format(ip)}\r\nUser-Agent: LANORA/1.1\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(req, cts.Token).ConfigureAwait(false);
        var data = await ReadLimited(stream, 16 * 1024, cts.Token).ConfigureAwait(false);
        var text = Encoding.Latin1.GetString(data);
        var m = TitleTag().Match(text);
        if (m.Success)
        {
            var title = SafeText.Clean(WebUtility.HtmlDecode(m.Groups[1].Value), 160);
            if (!string.IsNullOrEmpty(title)) scripts.Add(new ScriptEvidence($"http-title ({port})", title));
        }
    }

    private static async Task SslEnum(uint ip, int port, List<ScriptEvidence> scripts, CancellationToken ct)
    {
        var supported = new List<string>();
        foreach (var proto in new[] { SslProtocols.Tls12, SslProtocols.Tls13 })
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Timeout);
            try
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(new IPEndPoint(Ipv4.ToAddress(ip), port), cts.Token).ConfigureAwait(false);
                await using var net = new NetworkStream(socket, ownsSocket: true);
                await using var ssl = new SslStream(net, false, (_, _, _, _) => true);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = Ipv4.Format(ip),
                    EnabledSslProtocols = proto,
                    CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                }, cts.Token).ConfigureAwait(false);
                supported.Add(proto == SslProtocols.Tls13 ? "TLS 1.3" : "TLS 1.2");
            }
            catch
            {
                // This version is not supported.
            }
        }
        if (supported.Count > 0)
            scripts.Add(new ScriptEvidence($"ssl-enum ({port})", "Desteklenen: " + string.Join(", ", supported)));
    }

    private static async Task SshHostKey(uint ip, int port, List<ScriptEvidence> scripts, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        await using var stream = await ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
        var data = await ReadLimited(stream, 512, cts.Token).ConfigureAwait(false);
        var banner = SafeText.PrintableAscii(data, 200);
        if (banner.StartsWith("SSH-", StringComparison.Ordinal))
            scripts.Add(new ScriptEvidence($"ssh-banner ({port})", banner));
    }

    internal static async Task FtpAnon(uint ip, int port, List<ScriptEvidence> scripts, CancellationToken ct)
    {
        // Each step has its own time limit; real cancellation (ct) is distinguished from a timeout (F10).
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        connectCts.CancelAfter(Timeout);
        NetworkStream stream;
        try { stream = await ConnectAsync(ip, port, connectCts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return; }

        await using (stream)
        {
            try
            {
                var greeting = await ReadReplyAsync(stream, ct).ConfigureAwait(false);
                if (greeting.Code != 220) return;

                // Anonymous access attempt: only observes whether the server accepts it; no data is transferred.
                await SendAsync(stream, "USER anonymous", ct).ConfigureAwait(false);
                var user = await ReadReplyAsync(stream, ct).ConfigureAwait(false);
                if (user.Code == 230)
                {
                    scripts.Add(new ScriptEvidence($"ftp-anon ({port})", "Anonymous login accepted without a password"));
                }
                else if (user.Code == 331)
                {
                    await SendAsync(stream, "PASS lanora@example.com", ct).ConfigureAwait(false);
                    var pass = await ReadReplyAsync(stream, ct).ConfigureAwait(false);
                    scripts.Add(new ScriptEvidence($"ftp-anon ({port})", pass.Code == 230
                        ? "Anonymous login accepted (anonymous)"
                        : "Anonymous login rejected"));
                }
                else
                {
                    scripts.Add(new ScriptEvidence($"ftp-anon ({port})", "Anonymous login rejected"));
                }
                try { await SendAsync(stream, "QUIT", ct).ConfigureAwait(false); } catch { }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                scripts.Add(new ScriptEvidence($"ftp-anon ({port})", "Could not be checked (response timed out)"));
            }
        }
    }

    private static Task SendAsync(NetworkStream stream, string line, CancellationToken ct) =>
        stream.WriteAsync(Encoding.ASCII.GetBytes(line + "\r\n"), ct).AsTask();

    private sealed record LineReply(int Code, string Text);

    /// <summary>
    /// Reads a line-based protocol reply (FTP/SMTP): collects multi-line "220-..." replies until the last line
    /// starts with "NNN ". Total size is capped at 8 KiB and each read at 3 s.
    /// </summary>
    private static async Task<LineReply> ReadReplyAsync(NetworkStream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var buffer = new byte[1024];
        while (sb.Length < 8 * 1024)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Timeout);
            var n = await stream.ReadAsync(buffer, cts.Token).ConfigureAwait(false);
            if (n == 0) break;
            sb.Append(Encoding.Latin1.GetString(buffer, 0, n));
            var lines = sb.ToString().Split('\n');
            // Among complete lines, a final line starting with "NNN " ends the reply.
            for (var i = 0; i < lines.Length - 1; i++)
            {
                var l = lines[i].TrimEnd('\r');
                if (l.Length >= 4 && char.IsDigit(l[0]) && char.IsDigit(l[1]) && char.IsDigit(l[2]) && l[3] == ' ')
                    return new LineReply(int.Parse(l[..3]), SafeText.Clean(l, 200) ?? "");
            }
        }
        var text = sb.ToString();
        return new LineReply(text.Length >= 3 && int.TryParse(text[..3], out var code) ? code : 0, SafeText.Clean(text, 200) ?? "");
    }

    private static async Task<byte[]> ReadLimited(NetworkStream stream, int max, CancellationToken ct)
    {
        var buffer = new byte[max];
        var total = 0;
        try
        {
            while (total < max)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(total, max - total), ct).ConfigureAwait(false);
                if (n == 0) break;
                total += n;
                // Line endings are searched across all received data (not only the first bytes).
                if (Array.IndexOf(buffer, (byte)'\n', 0, total) >= 0) break;
            }
        }
        catch (Exception) when (total > 0) { }
        return buffer[..total];
    }
}
