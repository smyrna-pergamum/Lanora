using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Lanora.Infrastructure;
using Lanora.Net;

namespace Lanora.Scanning;

/// <summary>
/// FR11: Limited evidence collection with defined safe probes. HTTP headers (HEAD), TLS handshake
/// (no application data is sent) and expected passive banners. Limited to 2 s and 8 KiB of data.
/// A port number alone is not evidence of a product.
/// </summary>
public sealed partial class ServiceProber
{
    public const int MaxBytes = 8 * 1024;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);

    private static readonly HashSet<int> HttpPorts = new() { 80, 81, 3000, 4000, 4567, 5000, 7777, 8000, 8001, 8008, 8080, 8081, 8088, 8090, 8181, 8888, 9000, 9001, 9080, 9090, 9999, 10000, 32400, 631, 2869, 5357, 49152, 8200 };
    private static readonly HashSet<int> TlsPorts = new() { 443, 444, 465, 636, 993, 995, 2376, 4443, 5001, 5061, 5986, 6443, 8002, 8089, 8443, 8883, 9443, 10250 };
    private static readonly HashSet<int> BannerPorts = new() { 21, 22, 23, 25, 110, 143, 587, 2121, 2222, 3306, 5900, 5901 };

    [GeneratedRegex(@"^SSH-(\d\.\d+)-([^\s]+)(?:\s+(.*))?$")]
    private static partial Regex SshBanner();

    [GeneratedRegex(@"^([A-Za-z][\w .\-]*?)[/ ]v?(\d+(?:\.\d+){0,3}[\w\-]*)")]
    private static partial Regex ProductVersion();

    public static bool HasProbe(int port) => HttpPorts.Contains(port) || TlsPorts.Contains(port) || BannerPorts.Contains(port);

    public async Task<ServiceEvidence> ProbeAsync(uint ip, int port, CancellationToken ct)
    {
        var ev = new ServiceEvidence { ServiceName = PortCatalog.ServiceName(port), Method = "port_table" };
        if (!HasProbe(port)) return ev;
        try
        {
            if (TlsPorts.Contains(port)) await ProbeTlsAsync(ip, port, ev, ct).ConfigureAwait(false);
            else if (HttpPorts.Contains(port)) await ProbeHttpAsync(ip, port, ev, ct).ConfigureAwait(false);
            else await ProbeBannerAsync(ip, port, ev, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            ev.Summary ??= "no_banner_within_limit";
        }
        catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException)
        {
            ev.Summary ??= "probe_failed";
        }
        return ev;
    }

    private static async Task<Socket> ConnectAsync(uint ip, int port, CancellationToken ct)
    {
        var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await s.ConnectAsync(new IPEndPoint(Ipv4.ToAddress(ip), port), ct).ConfigureAwait(false);
            return s;
        }
        catch
        {
            s.Dispose();
            throw;
        }
    }

    private static async Task<byte[]> ReadLimitedAsync(Stream stream, CancellationToken ct, Func<byte[], int, bool>? enough = null)
    {
        var buffer = new byte[MaxBytes];
        var total = 0;
        try
        {
            while (total < MaxBytes)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(total, MaxBytes - total), ct).ConfigureAwait(false);
                if (n == 0) break;
                total += n;
                if (enough?.Invoke(buffer, total) == true) break;
            }
        }
        catch (OperationCanceledException) when (total > 0)
        {
            // Time is up; whatever was received is used.
        }
        catch (IOException) when (total > 0)
        {
        }
        return buffer[..total];
    }

    private static async Task ProbeHttpAsync(uint ip, int port, ServiceEvidence ev, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        using var socket = await ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        var req = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.0\r\nHost: {Ipv4.Format(ip)}\r\nUser-Agent: LANORA/1.0\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(req, cts.Token).ConfigureAwait(false);
        var data = await ReadLimitedAsync(stream, cts.Token, (b, n) => IndexOf(b, n, "\r\n\r\n"u8) >= 0).ConfigureAwait(false);
        var text = Encoding.Latin1.GetString(data);
        if (!text.StartsWith("HTTP/", StringComparison.Ordinal))
        {
            ev.Summary = data.Length == 0 ? "no_http_response" : "non_http_response";
            return;
        }
        ev.ServiceName = "HTTP";
        ev.Method = "http_head";
        var lines = text.Split("\r\n");
        var status = SafeText.Clean(lines[0], 60);
        string? server = null;
        foreach (var line in lines.Skip(1))
        {
            if (line.Length == 0) break;
            if (line.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))
                server = SafeText.Clean(line[7..], 120);
        }
        ev.Summary = server is null ? $"{status}" : $"{status}; Server: {server}";
        if (server is not null) ApplyProduct(ev, server);
    }

    private static async Task ProbeTlsAsync(uint ip, int port, ServiceEvidence ev, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        using var socket = await ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
        await using var net = new NetworkStream(socket, ownsSocket: false);
        X509Certificate2? cert = null;
        SslPolicyErrors errors = SslPolicyErrors.None;
        await using var ssl = new SslStream(net, leaveInnerStreamOpen: true, (_, c, _, e) =>
        {
            if (c is not null) cert = new X509Certificate2(c);
            errors = e;
            return true; // Observation only: the verification result is recorded separately and the connection is not continued.
        });
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = Ipv4.Format(ip),
            EnabledSslProtocols = SslProtocols.None,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        };
        await ssl.AuthenticateAsClientAsync(options, cts.Token).ConfigureAwait(false);
        ev.Method = "tls_handshake";
        ev.ServiceName ??= "TLS";
        var status = errors == SslPolicyErrors.None ? "valid" :
            errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors) ? "untrusted_chain" :
            errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) ? "name_mismatch" : "not_available";
        ev.TlsCertificateStatus = status;
        var sb = new StringBuilder($"TLS {ProtocolName(ssl.SslProtocol)}");
        if (cert is not null)
        {
            sb.Append("; CN=").Append(SafeText.Clean(cert.GetNameInfo(X509NameType.SimpleName, false), 80));
            sb.Append("; issuer=").Append(SafeText.Clean(cert.GetNameInfo(X509NameType.SimpleName, true), 80));
            sb.Append("; valid_to=").Append(cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"));
            cert.Dispose();
        }
        sb.Append("; cert_check=").Append(status);
        ev.Summary = sb.ToString();
    }

    private static string ProtocolName(SslProtocols p) => p switch
    {
        SslProtocols.Tls13 => "1.3",
        SslProtocols.Tls12 => "1.2",
#pragma warning disable SYSLIB0039
        SslProtocols.Tls11 => "1.1",
        SslProtocols.Tls => "1.0",
#pragma warning restore SYSLIB0039
        _ => p.ToString(),
    };

    private static async Task ProbeBannerAsync(uint ip, int port, ServiceEvidence ev, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        using var socket = await ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        var data = await ReadLimitedAsync(stream, cts.Token, (b, n) => n > 0 && (b[n - 1] == '\n' || (b[0] == 0xFF && n >= 3 && port is 23))).ConfigureAwait(false);
        Interpret(port, data, ev);
    }

    /// <summary>Banner interpretation; static and pure so it can be tested.</summary>
    internal static void Interpret(int port, byte[] data, ServiceEvidence ev)
    {
        if (data.Length == 0)
        {
            ev.Summary = "no_banner_within_limit";
            return;
        }
        ev.Method = "banner";
        var text = SafeText.PrintableAscii(StripTelnet(data), 256);
        var lower = text.ToLowerInvariant();

        if (port is 23 || (data[0] == 0xFF && data.Length >= 3 && data[1] is >= 0xFB and <= 0xFE))
        {
            var iac = data[0] == 0xFF && data.Length >= 3 && data[1] is >= 0xFB and <= 0xFE;
            if (iac || lower.Contains("login:") || lower.Contains("username") || lower.Contains("password") || lower.Contains("telnet"))
            {
                ev.ServiceName = "Telnet";
                ev.TelnetVerified = true;
                ev.Summary = iac ? "telnet_negotiation" + (text.Length > 0 ? "; " + text : "") : text;
                return;
            }
        }

        if (text.StartsWith("SSH-", StringComparison.Ordinal))
        {
            ev.ServiceName = "SSH";
            var m = SshBanner().Match(text);
            if (m.Success) ApplyProduct(ev, m.Groups[2].Value.Replace('_', '/'));
            ev.Summary = text;
            return;
        }

        if (text.StartsWith("220", StringComparison.Ordinal))
        {
            if (port is 21 or 2121 || lower.Contains("ftp"))
            {
                ev.ServiceName = "FTP";
                ev.FtpVerified = true;
            }
            else if (lower.Contains("smtp") || lower.Contains("esmtp") || port is 25 or 587)
            {
                ev.ServiceName = "SMTP";
            }
            ev.Summary = text;
            var rest = text.Length > 4 ? text[4..] : string.Empty;
            ApplyProduct(ev, rest);
            return;
        }

        if (text.StartsWith("+OK", StringComparison.Ordinal)) { ev.ServiceName = "POP3"; ev.Summary = text; return; }
        if (text.StartsWith("* OK", StringComparison.Ordinal)) { ev.ServiceName = "IMAP"; ev.Summary = text; return; }
        if (text.StartsWith("RFB ", StringComparison.Ordinal)) { ev.ServiceName = "VNC"; ev.Summary = text; ev.Version = SafeText.Clean(text[4..], 20); return; }
        if (port is 3306 && data.Length > 5 && data[4] == 0x0A)
        {
            ev.ServiceName = "MySQL";
            var end = Array.IndexOf(data, (byte)0, 5);
            if (end > 5) ev.Version = SafeText.Clean(Encoding.ASCII.GetString(data, 5, Math.Min(end - 5, 40)), 40);
            ev.Summary = "mysql_handshake" + (ev.Version is null ? "" : "; " + ev.Version);
            return;
        }
        ev.Summary = text.Length == 0 ? "binary_response" : text;
    }

    private static void ApplyProduct(ServiceEvidence ev, string raw)
    {
        var m = ProductVersion().Match(raw.Trim());
        if (m.Success)
        {
            ev.Product = SafeText.Clean(m.Groups[1].Value, 60);
            ev.Version = SafeText.Clean(m.Groups[2].Value, 40);
        }
        else
        {
            ev.Product = SafeText.Clean(raw, 60);
        }
    }

    private static byte[] StripTelnet(byte[] data)
    {
        var o = new List<byte>(data.Length);
        for (var i = 0; i < data.Length; i++)
        {
            if (data[i] == 0xFF && i + 1 < data.Length)
            {
                var cmd = data[i + 1];
                if (cmd is >= 0xFB and <= 0xFE) { i += 2; continue; }
                if (cmd == 0xFA)
                {
                    var j = i + 2;
                    while (j + 1 < data.Length && !(data[j] == 0xFF && data[j + 1] == 0xF0)) j++;
                    i = j + 1;
                    continue;
                }
                i += 1;
                continue;
            }
            o.Add(data[i]);
        }
        return o.ToArray();
    }

    private static int IndexOf(byte[] buffer, int length, ReadOnlySpan<byte> needle) =>
        buffer.AsSpan(0, length).IndexOf(needle);
}
