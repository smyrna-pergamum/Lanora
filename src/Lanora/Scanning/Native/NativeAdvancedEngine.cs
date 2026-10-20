using System.Net.NetworkInformation;
using Lanora.Infrastructure;
using Lanora.Net;
using Lanora.Scanning.Advanced;

namespace Lanora.Scanning.Native;

public sealed record NativeProgress(double Percent, string Phase, int HostsResponded, int OpenPorts);

/// <summary>
/// Built-in advanced scan engine (no external tool required). TCP Connect + native UDP + service/OS detection +
/// reverse DNS + traceroute + service checks. Everything runs with normal user rights.
/// Hostname/external targets have been validated with authorization confirmation in AdvancedScanValidator.
/// </summary>
public sealed class NativeAdvancedEngine
{
    private static readonly int[] DiscoveryPorts = { 80, 443, 22, 445, 3389 };
    private readonly IScanBackend _tcp;
    private readonly UdpProber _udp = new();
    private readonly ServiceProber _prober;
    private readonly NativeScripts _scripts = new();
    private readonly OuiDatabase _oui;

    public NativeAdvancedEngine(IScanBackend tcp, ServiceProber prober, OuiDatabase oui)
    {
        _tcp = tcp;
        _prober = prober;
        _oui = oui;
    }

    /// <summary>
    /// Adds discovered devices to the <paramref name="hosts"/> list; on cancel/error the devices and observations
    /// found so far stay in the list (the caller saves them). The returned list is the same reference.
    /// </summary>
    public async Task<List<HostResult>> RunAsync(NativeScanSpec spec, IProgress<NativeProgress>? progress, CancellationToken ct, List<HostResult>? hosts = null)
    {
        hosts ??= new List<HostResult>();
        var rate = new RateLimiter(spec.RatePerSecond);
        var neighbors = SafeNeighbors(spec.InterfaceIndex);

        // 1) Discovery: ICMP + ARP + limited TCP. External targets have no ARP; ICMP/TCP are used.
        progress?.Report(new NativeProgress(2, "discovery", 0, 0));
        await Parallel.ForEachAsync(spec.Targets, Par(spec.Concurrency, ct), async (ip, token) =>
        {
            var h = new HostResult { Ip = ip, IsLocal = ip == spec.LocalIp, IsGateway = ip == spec.Gateway };
            if (h.IsLocal) { h.DiscoveryEvidence.Add("local"); h.Mac = spec.LocalMac; h.MacSource = "local_adapter"; }
            var (reply, ttl) = await _tcp.PingAsync(ip, 800, token).ConfigureAwait(false);
            if (reply) { h.DiscoveryEvidence.Add("icmp"); h.IcmpTtl = ttl; }
            if (neighbors is not null && neighbors.TryGetValue(ip, out var n) && n.State == NeighborState.Reachable && n.Mac is not null)
            {
                h.DiscoveryEvidence.Add("arp"); h.Mac ??= n.Mac; h.MacSource ??= "arp_neighbor_table";
            }
            if (!h.Alive)
            {
                // Limited TCP reachability evidence.
                foreach (var p in DiscoveryPorts)
                {
                    await rate.WaitAsync(token).ConfigureAwait(false);
                    Interlocked.Increment(ref spec.Attempts);
                    var r = await _tcp.ProbeTcpAsync(ip, p, 800, token).ConfigureAwait(false);
                    if (r.State is PortState.Open or PortState.Closed) { h.DiscoveryEvidence.Add("tcp"); break; }
                }
            }
            if (spec.TreatAllOnline && !h.Alive) h.DiscoveryEvidence.Add("assumed");
            // A found device is added to the shared list immediately, so it is kept even if discovery is cancelled.
            if (h.Alive) { lock (hosts) hosts.Add(h); }
        }).ConfigureAwait(false);
        hosts.Sort((a, b) => a.Ip.CompareTo(b.Ip));
        progress?.Report(new NativeProgress(25, "discovery", hosts.Count, 0));

        // 2) TCP Connect port scan
        var tcpPairs = hosts.SelectMany(h => spec.TcpPorts.Select(p => (Host: h, Port: p))).ToList();
        var openCount = 0;
        var tcpDone = 0;
        if (tcpPairs.Count > 0)
        {
            var perHost = hosts.ToDictionary(h => h.Ip, _ => new SemaphoreSlim(spec.PerHostConcurrency));
            await Parallel.ForEachAsync(tcpPairs, Par(spec.Concurrency, ct), async (pair, token) =>
            {
                var sem = perHost[pair.Host.Ip];
                await sem.WaitAsync(token).ConfigureAwait(false);
                try
                {
                    await rate.WaitAsync(token).ConfigureAwait(false);
                    Interlocked.Increment(ref spec.Attempts);
                    var r = await _tcp.ProbeTcpAsync(pair.Host.Ip, pair.Port, spec.TimeoutMs, token).ConfigureAwait(false);
                    var obs = new PortObservationResult { Protocol = "tcp", Port = pair.Port, State = r.State, ReasonCode = r.ReasonCode, Method = "tcp_connect", Attempts = 1, ObservedAt = DateTimeOffset.UtcNow };
                    lock (pair.Host) pair.Host.Ports[pair.Port] = obs;
                    if (r.State == PortState.Open) Interlocked.Increment(ref openCount);
                }
                finally
                {
                    sem.Release();
                    var d = Interlocked.Increment(ref tcpDone);
                    if (d % 32 == 0) progress?.Report(new NativeProgress(25 + 35.0 * d / tcpPairs.Count, "port_scan", hosts.Count, openCount));
                }
            }).ConfigureAwait(false);
            foreach (var s in perHost.Values) s.Dispose();
        }
        progress?.Report(new NativeProgress(60, "port_scan", hosts.Count, openCount));

        // 3) Native UDP scan
        if (spec.UdpPorts.Count > 0)
        {
            var udpPairs = hosts.SelectMany(h => spec.UdpPorts.Select(p => (Host: h, Port: p))).ToList();
            await Parallel.ForEachAsync(udpPairs, Par(Math.Max(8, spec.Concurrency / 2), ct), async (pair, token) =>
            {
                await rate.WaitAsync(token).ConfigureAwait(false);
                Interlocked.Increment(ref spec.Attempts);
                var r = await _udp.ProbeAsync(pair.Host.Ip, pair.Port, spec.TimeoutMs + 400, token).ConfigureAwait(false);
                var obs = new PortObservationResult { Protocol = "udp", Port = pair.Port, State = r.State, ReasonCode = r.ReasonCode, Method = "udp_probe", Attempts = 1, ObservedAt = DateTimeOffset.UtcNow };
                if (r.State == PortState.Open) { obs.Service = new ServiceEvidence { ServiceName = UdpProber.ServiceName(pair.Port), Method = "udp_probe" }; Interlocked.Increment(ref openCount); }
                lock (pair.Host) pair.Host.Ports[-pair.Port] = obs; // UDP uses a separate key
            }).ConfigureAwait(false);
        }
        progress?.Report(new NativeProgress(72, "enrichment", hosts.Count, openCount));

        // 4) Enrichment: service/version + reverse DNS + traceroute + OS + service checks
        foreach (var h in hosts)
        {
            ct.ThrowIfCancellationRequested();
            var openTcp = h.Ports.Values.Where(p => p.Protocol == "tcp" && p.State == PortState.Open).Select(p => p.Port).ToList();

            // Service/version evidence (TCP) — only when the option is on; otherwise the port table estimate is used.
            foreach (var obs in h.Ports.Values.Where(p => p.Protocol == "tcp" && p.State == PortState.Open))
            {
                if (spec.ServiceVersion)
                {
                    await rate.WaitAsync(ct).ConfigureAwait(false);
                    obs.Service = await _prober.ProbeAsync(h.Ip, obs.Port, ct).ConfigureAwait(false);
                }
                else
                {
                    obs.Service = new ServiceEvidence { ServiceName = PortCatalog.ServiceName(obs.Port) };
                }
            }

            // Reverse DNS (device name)
            if (spec.ReverseDns && h.Hostname is null)
            {
                var name = await ReverseDns.ResolveAsync(h.Ip, ct).ConfigureAwait(false);
                if (name is not null) { h.Hostname = name; h.HostnameType = "PTR"; }
            }

            // Vendor
            h.Vendor ??= _oui.Lookup(h.Mac);

            // Device type always; operating system estimate only when the option is on (F09).
            HostClassifier.Classify(h, spec.OsDetection);

            // NSE benzeri kontroller
            if (spec.Scripts && openTcp.Count > 0)
            {
                var sc = await _scripts.RunAsync(h.Ip, openTcp, spec.IncludeVuln, ct).ConfigureAwait(false);
                h.Scripts.AddRange(sc);
            }

            // Traceroute
            if (spec.Traceroute && !h.IsLocal)
            {
                var hops = await Traceroute.RunAsync(h.Ip, 20, 1000, ct).ConfigureAwait(false);
                h.Trace.AddRange(hops);
                if (hops.Count > 0) h.Distance = hops.Count;
            }
        }
        progress?.Report(new NativeProgress(95, "scoring", hosts.Count, openCount));
        return hosts;
    }

    private static ParallelOptions Par(int max, CancellationToken ct) => new() { MaxDegreeOfParallelism = Math.Max(1, max), CancellationToken = ct };

    private static Dictionary<uint, NeighborEntry>? SafeNeighbors(uint ifIndex)
    {
        if (ifIndex == 0) return null;
        try
        {
            return NativeMethods.GetNeighbors().Where(n => n.InterfaceIndex == ifIndex)
                .GroupBy(n => n.Ip).ToDictionary(g => g.Key, g => g.OrderByDescending(n => n.State == NeighborState.Reachable).First());
        }
        catch { return null; }
    }
}

/// <summary>Validated scan parameters for the built-in engine.</summary>
public sealed class NativeScanSpec
{
    public required IReadOnlyList<uint> Targets { get; init; }
    public required IReadOnlyList<int> TcpPorts { get; init; }
    public IReadOnlyList<int> UdpPorts { get; init; } = Array.Empty<int>();
    public uint? LocalIp { get; init; }
    public uint? Gateway { get; init; }
    public string? LocalMac { get; init; }
    public uint InterfaceIndex { get; init; }
    public int TimeoutMs { get; init; } = 1000;
    public int Concurrency { get; init; } = 64;
    public int PerHostConcurrency { get; init; } = 4;
    public int RatePerSecond { get; init; } = 100;
    public bool ReverseDns { get; init; } = true;
    public bool OsDetection { get; init; } = true;
    public bool ServiceVersion { get; init; } = true;
    /// <summary>Total number of probes sent (TCP + UDP + discovery); used in the summary and report.</summary>
    public long Attempts;
    public bool Traceroute { get; init; }
    public bool Scripts { get; init; }
    public bool IncludeVuln { get; init; }
    public bool TreatAllOnline { get; init; }
}
