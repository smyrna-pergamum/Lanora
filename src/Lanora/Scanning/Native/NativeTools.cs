using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Lanora.Net;

namespace Lanora.Scanning.Native;

/// <summary>Native traceroute with TTL-incrementing ICMP. Needs no administrator rights or raw sockets (Ping class).</summary>
public static class Traceroute
{
    public static async Task<List<TraceHop>> RunAsync(uint ip, int maxHops, int timeoutMs, CancellationToken ct)
    {
        var hops = new List<TraceHop>();
        var target = Ipv4.ToAddress(ip);
        var buffer = new byte[32];
        for (var ttl = 1; ttl <= maxHops; ttl++)
        {
            ct.ThrowIfCancellationRequested();
            using var ping = new Ping();
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var reply = await ping.SendPingAsync(target, TimeSpan.FromMilliseconds(timeoutMs), buffer, new PingOptions(ttl, true), ct).ConfigureAwait(false);
                var rtt = sw.Elapsed.TotalMilliseconds;
                if (reply.Status == IPStatus.TtlExpired || reply.Status == IPStatus.TimeExceeded)
                {
                    var addr = reply.Address?.ToString();
                    hops.Add(new TraceHop(ttl, addr, null, Math.Round(rtt, 1)));
                }
                else if (reply.Status == IPStatus.Success)
                {
                    hops.Add(new TraceHop(ttl, reply.Address?.ToString() ?? Ipv4.Format(ip), null, Math.Round(rtt, 1)));
                    break;
                }
                else
                {
                    hops.Add(new TraceHop(ttl, null, null, null)); // unresponsive hop: *
                }
            }
            catch (PingException)
            {
                hops.Add(new TraceHop(ttl, null, null, null));
            }
        }
        return hops;
    }
}

/// <summary>Reverse DNS (PTR) lookup. Bounded and cancellable.</summary>
public static class ReverseDns
{
    public static async Task<string?> ResolveAsync(uint ip, CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(1500);
            var entry = await Dns.GetHostEntryAsync(Ipv4.Format(ip), timeout.Token).ConfigureAwait(false);
            var name = entry.HostName;
            if (string.IsNullOrWhiteSpace(name)) return null;
            // If a numeric IP came back, there is no meaningful name.
            return Ipv4.TryParse(name, out _) ? null : Infrastructure.SafeText.Clean(name, 253);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
        {
            return null;
        }
    }
}
