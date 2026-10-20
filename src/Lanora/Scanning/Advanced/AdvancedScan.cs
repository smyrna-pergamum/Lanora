using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Lanora.Infrastructure;
using Lanora.Net;

namespace Lanora.Scanning.Advanced;

/// <summary>Advanced scan technique (built-in engine). Connect needs no elevated rights; UDP sends service probes.</summary>
public enum ScanTechnique { Connect, Udp }

/// <summary>
/// Advanced scan request. Targets outside the local network or hostnames require the user's authorization confirmation.
/// The scan runs on the built-in (native) engine; no external tool needs to be installed.
/// </summary>
public sealed class AdvancedScanRequest
{
    public string? InterfaceId { get; set; }
    public List<string> Targets { get; set; } = new();
    public string Technique { get; set; } = "connect";   // connect | udp
    public bool IncludeUdp { get; set; }
    public string PortScope { get; set; } = "top";        // top | custom | all
    public int? TopPorts { get; set; }
    public List<int>? TcpPorts { get; set; }
    public List<int>? UdpPorts { get; set; }
    public bool ServiceVersion { get; set; } = true;
    public bool OsDetection { get; set; } = true;
    public bool Traceroute { get; set; }
    public bool ReverseDns { get; set; } = true;
    public bool ServiceChecks { get; set; }               // servis kontrolleri (http-title, ssl, ssh, ftp-anon)
    /// <summary>User's authorization statement for scanning external/hostname targets (compliance gate).</summary>
    public bool Authorized { get; set; }
}

public sealed record ResolvedTarget(string Input, string? Resolved, bool IsLocal, bool IsExternal, bool IsHostname);

/// <summary>Validated, resolved advanced scan plan. Carries only built-in engine parameters.</summary>
public sealed record AdvancedPlan(
    IReadOnlyList<ResolvedTarget> Targets,
    bool AuthorizationRequired,
    bool AnyExternal,
    string? InterfaceId,
    uint? LocalIp,
    uint? Gateway,
    ScanTechnique Technique,
    bool IncludeUdp,
    bool OsDetection,
    bool Traceroute,
    bool ReverseDns,
    bool ServiceChecks,
    bool ServiceVersion,
    IReadOnlyList<int> TcpPorts,
    IReadOnlyList<int> UdpPorts,
    IReadOnlyList<uint> IpTargets);

/// <summary>
/// Validates and resolves advanced scan targets. Literal IPs in the local adapter's private network are "local" and
/// need no extra authorization; hostnames or external/public targets are accepted only when Authorized=true.
/// Loopback/multicast/broadcast targets are always rejected. Total targets are capped at 1024.
/// </summary>
public static partial class AdvancedScanValidator
{
    public const int MaxTargets = 1024;
    public const long MaxTotalProbes = 2_000_000;
    private const int MaxExpandPerEntry = 1024;

    // The built-in engine's "most common" and default port sets.
    public static readonly int[] TopTcpPorts = { 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 1433, 1521, 2049, 2375, 3000, 5000, 5060, 5601, 6443, 7070, 8000, 8008, 8081, 8088, 8888, 9000, 9090, 9100, 9200, 10000, 27017, 161, 389, 636, 873, 902, 1194, 1400, 1883, 2082, 2083, 2222, 2869, 3283, 5222, 5357, 5555, 8009, 8181, 8291, 32400, 49152, 62078, 20, 37, 79, 88, 113, 119, 179, 427, 465, 512, 513, 514, 515, 548, 554, 587, 631, 646, 990, 992, 1080, 2000, 2121, 2376, 3128, 3260, 3690, 4000, 4443, 5001, 5009, 5061, 5800, 5901, 5986, 6000, 6667, 7000, 7100, 7547, 7777, 8001, 8089, 8090, 8200, 8333, 8883, 9001, 9080, 9443, 9999, 10250, 11211, 1025, 1026, 1027 };
    public static readonly int[] DefaultUdpPorts = { 53, 123, 161, 137, 1900, 5353, 69, 111, 500, 520 };

    [GeneratedRegex(@"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$|^(?:\d{1,3}\.){3}\d{1,3}-\d{1,3}$", RegexOptions.CultureInvariant)]
    private static partial Regex Ipv4Target();

    [GeneratedRegex(@"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.?$", RegexOptions.CultureInvariant)]
    private static partial Regex Hostname();

    public static bool IsValidTarget(string target)
    {
        if (string.IsNullOrWhiteSpace(target) || target.Length > 255 || target[0] == '-') return false;
        return Ipv4Target().IsMatch(target) || Hostname().IsMatch(target);
    }

    public static AdvancedPlan Build(AdvancedScanRequest req, AdapterInfo? adapter, Func<string, IReadOnlyList<string>> resolve, IReadOnlyList<int>? standardPorts = null)
    {
        if (req.Targets is null || req.Targets.Count == 0) throw new ApiException(400, "TARGET_EMPTY");
        if (req.Targets.Count > MaxTargets) throw new ApiException(400, "TARGET_LIMIT", new { max = MaxTargets });

        // Locality is determined only by a selectable adapter's private network. With no selectable adapter
        // no target counts as "local", which keeps the external-target authorization gate correct (F05).
        var canLocal = adapter is { Selectable: true };
        Cidr localNet = default;
        uint? localIp = null, gateway = null;
        if (canLocal)
        {
            localNet = adapter!.Network;
            localIp = adapter.IpValue;
            gateway = adapter.Gateway is null ? null : Ipv4.Parse(adapter.Gateway);
        }

        var resolved = new List<ResolvedTarget>();
        var anyExternal = false;
        var total = 0;

        foreach (var raw in req.Targets.Select(x => (x ?? "").Trim()).Where(x => x.Length > 0))
        {
            if (!IsValidTarget(raw)) throw new ApiException(400, "TARGET_INVALID", new { target = raw });
            var isHostname = !LooksNumeric(raw);
            if (isHostname)
            {
                if (!req.Authorized) throw new ApiException(403, "AUTHORIZATION_REQUIRED", new { target = raw, kind = "hostname" });
                var ips = resolve(raw);
                if (ips.Count == 0) throw new ApiException(400, "HOST_RESOLVE_FAILED", new { target = raw });
                foreach (var ip in ips.Where(x => Ipv4.TryParse(x, out _)))
                {
                    GuardReserved(ip);
                    anyExternal = true;
                    if (++total > MaxTargets) throw new ApiException(400, "TARGET_LIMIT", new { max = MaxTargets });
                    resolved.Add(new ResolvedTarget(raw, ip, false, true, true));
                }
                continue;
            }

            foreach (var ip in ExpandV4(raw))
            {
                GuardReserved(Ipv4.Format(ip));
                var isLocal = canLocal && localNet.Contains(ip);
                if (!isLocal)
                {
                    if (!req.Authorized) throw new ApiException(403, "AUTHORIZATION_REQUIRED", new { target = Ipv4.Format(ip), kind = "external" });
                    anyExternal = true;
                }
                if (++total > MaxTargets) throw new ApiException(400, "TARGET_LIMIT", new { max = MaxTargets });
                resolved.Add(new ResolvedTarget(raw, Ipv4.Format(ip), isLocal, !isLocal, false));
            }
        }

        if (resolved.Count == 0) throw new ApiException(400, "TARGET_EMPTY");

        var technique = req.Technique == "udp" ? ScanTechnique.Udp : ScanTechnique.Connect;
        var (tcpPorts, udpPorts) = ResolvePorts(req, standardPorts);
        var ipTargets = resolved
            .Select(r => r.Resolved ?? r.Input)
            .Select(s => Ipv4.TryParse(s, out var v) ? (uint?)v : null)
            .Where(v => v is not null).Select(v => v!.Value).Distinct().ToList();

        // Total probe budget to bound memory and time (e.g. "all ports × many targets" is rejected).
        var totalProbes = (long)ipTargets.Count * (tcpPorts.Count + udpPorts.Count);
        if (totalProbes > MaxTotalProbes)
            throw new ApiException(400, "ATTEMPT_BUDGET_EXCEEDED", new { max = MaxTotalProbes, planned = totalProbes });

        return new AdvancedPlan(resolved, anyExternal, anyExternal, req.InterfaceId, localIp, gateway,
            technique, req.IncludeUdp, req.OsDetection, req.Traceroute, req.ReverseDns, req.ServiceChecks, req.ServiceVersion,
            tcpPorts, udpPorts, ipTargets);
    }

    private static (IReadOnlyList<int> Tcp, IReadOnlyList<int> Udp) ResolvePorts(AdvancedScanRequest req, IReadOnlyList<int>? standardPorts)
    {
        var wantUdp = req.IncludeUdp || req.Technique == "udp";
        // If the technique is UDP only, no TCP is planned for any scope (F07).
        var wantTcp = req.Technique != "udp";
        switch (req.PortScope)
        {
            case "all":
                return (wantTcp ? Enumerable.Range(1, 65535).ToArray() : Array.Empty<int>(), wantUdp ? DefaultUdpPorts : Array.Empty<int>());
            case "custom":
                var tcp = wantTcp && req.TcpPorts is { Count: > 0 } ? Validate(req.TcpPorts) : Array.Empty<int>();
                var udp = wantUdp && req.UdpPorts is { Count: > 0 } ? Validate(req.UdpPorts) : (wantUdp ? DefaultUdpPorts : Array.Empty<int>());
                if (tcp.Length == 0 && udp.Length == 0) throw new ApiException(400, "PORTS_REQUIRED");
                if (tcp.Length + udp.Length > 2048) throw new ApiException(400, "PORT_LIMIT", new { max = 2048 });
                return (tcp, udp);
            default: // top
                if (req.TopPorts is { } requested && (requested < 1 || requested > 65535))
                    throw new ApiException(400, "PORT_LIMIT", new { max = 65535 });
                var n = req.TopPorts ?? 100;
                return (wantTcp ? TopPorts(n, standardPorts) : Array.Empty<int>(), wantUdp ? DefaultUdpPorts : Array.Empty<int>());
        }
    }

    /// <summary>
    /// Produces exactly n ports: priority (common) ports first, then filled in 1..65535 order.
    /// The requested count is never silently reduced (F08).
    /// </summary>
    internal static int[] TopPorts(int n, IReadOnlyList<int>? standardPorts)
    {
        var pool = (standardPorts is { Count: > 0 } ? standardPorts.Concat(TopTcpPorts) : TopTcpPorts).Distinct().ToList();
        var result = new List<int>(n);
        var seen = new HashSet<int>();
        foreach (var p in pool)
        {
            if (result.Count >= n) break;
            if (seen.Add(p)) result.Add(p);
        }
        for (var p = 1; p <= 65535 && result.Count < n; p++)
            if (seen.Add(p)) result.Add(p);
        return result.Order().ToArray();
    }

    private static int[] Validate(List<int> ports)
    {
        foreach (var p in ports) if (p is < 1 or > 65535) throw new ApiException(400, "PORT_INVALID", new { port = p });
        return ports.Distinct().Order().ToArray();
    }

    private static void GuardReserved(string ip)
    {
        if (Ipv4.TryParse(ip, out var v) && (Ipv4.IsLoopback(v) || Ipv4.IsMulticast(v) || Ipv4.IsReservedOrUnspecified(v)))
            throw new ApiException(403, "TARGET_RESERVED", new { target = ip });
    }

    // Only real IPv4 / CIDR / range forms are numeric. Names starting with a digit, such as "3d-printer.local",
    // are treated as hostnames (F13).
    private static bool LooksNumeric(string s) => Ipv4Target().IsMatch(s);

    private static IEnumerable<uint> ExpandV4(string item)
    {
        if (item.Contains('/'))
        {
            if (!Cidr.TryParse(item, out var c)) throw new ApiException(400, "TARGET_INVALID", new { target = item });
            if (c.AddressCount > MaxExpandPerEntry) throw new ApiException(400, "TARGET_LIMIT", new { max = MaxTargets, target = item });
            // For /30 and larger blocks the network and broadcast addresses are removed from the target list (F06).
            var skipEdges = c.Prefix <= 30;
            for (long ip = c.Network; ip <= c.Broadcast; ip++)
            {
                if (skipEdges && ((uint)ip == c.Network || (uint)ip == c.Broadcast)) continue;
                yield return (uint)ip;
            }
            yield break;
        }
        var dash = item.IndexOf('-');
        if (dash > 0)
        {
            var left = item[..dash].Trim();
            var right = item[(dash + 1)..].Trim();
            if (!Ipv4.TryParse(left, out var start)) throw new ApiException(400, "TARGET_INVALID", new { target = item });
            uint end = Ipv4.TryParse(right, out var full) ? full : byte.TryParse(right, out var last) ? (start & 0xFFFFFF00) | last : throw new ApiException(400, "TARGET_INVALID", new { target = item });
            if (end < start || end - start + 1 > MaxExpandPerEntry) throw new ApiException(400, "TARGET_INVALID", new { target = item });
            for (long ip = start; ip <= end; ip++) yield return (uint)ip;
            yield break;
        }
        if (!Ipv4.TryParse(item, out var single)) throw new ApiException(400, "TARGET_INVALID", new { target = item });
        yield return single;
    }

    /// <summary>Bounded, safe DNS resolution (at most 8 results).</summary>
    public static IReadOnlyList<string> ResolveHost(string host)
    {
        // Time-limited resolution: an unresponsive DNS server does not block the request.
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try
        {
            return Dns.GetHostAddressesAsync(host, cts.Token).GetAwaiter().GetResult()
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.ToString()).Distinct().Take(8).ToList();
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException or OperationCanceledException)
        {
            return Array.Empty<string>();
        }
    }
}
