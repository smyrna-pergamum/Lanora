using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Lanora.Net;

namespace Lanora.Scanning;

/// <summary>Common contract for scan backends (built-in engine and possible future engines).</summary>
public interface IScanBackend
{
    string Name { get; }
    string Version { get; }
    Task<ProbeResult> ProbeTcpAsync(uint ip, int port, int timeoutMs, CancellationToken ct);
    Task<(bool Reply, int? Ttl)> PingAsync(uint ip, int timeoutMs, CancellationToken ct);
}

/// <summary>
/// FR05: TCP Connect with normal user rights. Connection established → open; explicit refusal (RST) → closed;
/// timeout → no_response; local network failure → error with a separate reason code. No raw sockets needed.
/// </summary>
public sealed class SocketBackend : IScanBackend
{
    // Winsock IPPROTO_TCP options. Without TCP_NOSYNRETRIES Windows retries SYN for ~2 s after an RST
    // and a closed port times out, which breaks the distinction between "closed" and "no response".
    private const SocketOptionName TcpNoSynRetries = (SocketOptionName)9;
    private const SocketOptionName TcpFailConnectOnIcmpError = (SocketOptionName)18;

    public string Name => "socket";
    public string Version => "socket-1.0";

    public async Task<ProbeResult> ProbeTcpAsync(uint ip, int port, int timeoutMs, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var sw = Stopwatch.StartNew();
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        TrySet(socket, TcpNoSynRetries);
        TrySet(socket, TcpFailConnectOnIcmpError);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(timeoutMs);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(Ipv4.ToAddress(ip), port), timeout.Token).ConfigureAwait(false);
            var r = new ProbeResult(PortState.Open, "syn_ack", (int)sw.ElapsedMilliseconds);
            try { socket.Shutdown(SocketShutdown.Both); } catch { }
            return r;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new ProbeResult(PortState.NoResponse, "timeout", (int)sw.ElapsedMilliseconds);
        }
        catch (SocketException ex)
        {
            var ms = (int)sw.ElapsedMilliseconds;
            return ex.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => new ProbeResult(PortState.Closed, "conn_refused", ms),
                SocketError.TimedOut => new ProbeResult(PortState.NoResponse, "timeout", ms),
                SocketError.HostUnreachable => new ProbeResult(PortState.Error, "host_unreachable", ms),
                SocketError.NetworkUnreachable => new ProbeResult(PortState.Error, "network_unreachable", ms),
                SocketError.HostDown => new ProbeResult(PortState.Error, "host_down", ms),
                SocketError.NetworkDown => new ProbeResult(PortState.Error, "network_down", ms),
                SocketError.AccessDenied => new ProbeResult(PortState.Error, "access_denied", ms),
                SocketError.NoBufferSpaceAvailable or SocketError.TooManyOpenSockets => new ProbeResult(PortState.Error, "local_resources", ms),
                _ => new ProbeResult(PortState.Error, "socket_" + ex.SocketErrorCode.ToString().ToLowerInvariant(), ms),
            };
        }
    }

    public async Task<(bool Reply, int? Ttl)> PingAsync(uint ip, int timeoutMs, CancellationToken ct)
    {
        using var ping = new Ping();
        try
        {
            var reply = await ping.SendPingAsync(Ipv4.ToAddress(ip), TimeSpan.FromMilliseconds(timeoutMs), null, null, ct).ConfigureAwait(false);
            return reply.Status == IPStatus.Success ? (true, reply.Options?.Ttl) : (false, null);
        }
        catch (PingException)
        {
            return (false, null);
        }
    }

    private static void TrySet(Socket s, SocketOptionName name)
    {
        try { s.SetSocketOption(SocketOptionLevel.Tcp, name, true); }
        catch (SocketException) { }
    }
}

/// <summary>Global new-connection rate limit (N per second, token bucket).</summary>
public sealed class RateLimiter
{
    private readonly double _rate;
    private readonly double _burst;
    private readonly object _gate = new();
    private double _tokens;
    private long _last = Stopwatch.GetTimestamp();

    public RateLimiter(int perSecond)
    {
        _rate = Math.Max(1, perSecond);
        _burst = Math.Max(1, perSecond / 10.0);
        _tokens = _burst;
    }

    public async Task WaitAsync(CancellationToken ct)
    {
        while (true)
        {
            int delayMs;
            lock (_gate)
            {
                var now = Stopwatch.GetTimestamp();
                _tokens = Math.Min(_burst, _tokens + (now - _last) / (double)Stopwatch.Frequency * _rate);
                _last = now;
                if (_tokens >= 1)
                {
                    _tokens -= 1;
                    return;
                }
                delayMs = (int)Math.Ceiling((1 - _tokens) / _rate * 1000);
            }
            await Task.Delay(Math.Max(1, delayMs), ct).ConfigureAwait(false);
        }
    }
}
