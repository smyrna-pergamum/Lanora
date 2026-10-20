using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using Lanora.Data;
using Lanora.Infrastructure;
using Lanora.Net;
using Lanora.Risk;

namespace Lanora.Scanning;

/// <summary>
/// ScanOrchestrator: single active job, time/probe budget, rate and concurrency limits, cancellation and event generation.
/// A scan is not tied to the HTTP request lifetime; it keeps running while the host process is alive, even if the UI closes.
/// </summary>
public sealed class ScanOrchestrator
{
    private static readonly int[] DiscoveryPorts = { 80, 443, 22, 445 };
    private const int IcmpTimeoutMs = 800;
    private const int DiscoveryTcpTimeoutMs = 800;

    private readonly NetworkInfoService _net;
    private readonly PortCatalog _catalog;
    private readonly RiskEngine _risk;
    private readonly ScanStore _store;
    private readonly BadgeService _badges;
    private readonly OuiDatabase _oui;
    private readonly IScanBackend _backend;
    private readonly ServiceProber _prober;
    private readonly Database _db;
    private readonly Native.NativeAdvancedEngine _native;
    private readonly object _gate = new();
    private readonly Dictionary<string, (string Hash, string ScanId)> _idempotency = new();
    private readonly LinkedList<IScanJob> _recent = new();
    private IScanJob? _active;
    private bool _starting;

    public ScanOrchestrator(NetworkInfoService net, PortCatalog catalog, RiskEngine risk, ScanStore store, BadgeService badges,
        OuiDatabase oui, IScanBackend backend, ServiceProber prober, Database db)
    {
        _net = net;
        _catalog = catalog;
        _risk = risk;
        _store = store;
        _badges = badges;
        _oui = oui;
        _backend = backend;
        _prober = prober;
        _db = db;
        _native = new Native.NativeAdvancedEngine(backend, prober, oui);
    }

    public static string AppVersion => typeof(ScanOrchestrator).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
    public string EngineVersion => $"lanora-{AppVersion}/{_backend.Version}";

    public IScanJob? Active
    {
        get { lock (_gate) return _active; }
    }

    public IScanJob? GetJob(string id)
    {
        lock (_gate)
        {
            if (_active?.Id == id) return _active;
            return _recent.FirstOrDefault(j => j.Id == id);
        }
    }

    // ---------- Planning and validation ----------

    public ScanPlan BuildPlan(ScanRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.InterfaceId)) throw new ApiException(400, "INTERFACE_REQUIRED");
        var adapter = _net.Find(req.InterfaceId) ?? throw new ApiException(400, "INTERFACE_NOT_FOUND");
        // Quick/standard/custom profiles are TCP Connect only; UDP and OS belong to the advanced scan.
        if (req.IncludeUdp || req.IncludeOsDetection)
            throw new ApiException(400, "USE_ADVANCED_SCAN");

        var profile = _catalog.Get(req.ProfileId ?? "quick") ?? throw new ApiException(400, "PROFILE_INVALID");
        if (profile.Available == false) throw new ApiException(400, "USE_ADVANCED_SCAN");

        int[] ports;
        if (profile.Ports is not null)
        {
            if (req.TcpPorts is { Count: > 0 } && !req.TcpPorts.ToHashSet().SetEquals(profile.Ports))
                throw new ApiException(400, "PROFILE_PORTS_CONFLICT");
            ports = profile.Ports;
        }
        else
        {
            if (req.TcpPorts is not { Count: > 0 }) throw new ApiException(400, "PORTS_REQUIRED");
            if (req.TcpPorts.Any(p => p is < 1 or > 65535)) throw new ApiException(400, "PORT_INVALID");
            ports = req.TcpPorts.Distinct().Order().ToArray();
            if (ports.Length > (profile.MaxPorts ?? 1024)) throw new ApiException(400, "PORT_LIMIT", new { max = profile.MaxPorts ?? 1024 });
        }

        var targets = TargetValidator.Validate(adapter, req.Targets);
        long maxAttempts;
        if (profile.MaxAttempts is { } budget)
        {
            if ((long)targets.Targets.Count * ports.Length > budget)
                throw new ApiException(400, "ATTEMPT_BUDGET_EXCEEDED", new { max = budget, planned = (long)targets.Targets.Count * ports.Length });
            maxAttempts = budget;
        }
        else
        {
            maxAttempts = (long)targets.Targets.Count * ports.Length * (1 + profile.Retries) + targets.Targets.Count * DiscoveryPorts.Length;
        }

        return new ScanPlan(adapter, targets, profile.Id, ports, profile.TimeoutMs, profile.Retries, maxAttempts, _catalog.Rate, _catalog.Version);
    }

    private static string PlanHash(ScanPlan p) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{p.Adapter.Id}|{p.ProfileId}|{string.Join(',', p.Ports)}|{string.Join(',', p.Targets.Targets)}")));

    // ---------- Advanced scan (built-in engine) ----------

    public Advanced.AdvancedPlan BuildAdvancedPlan(Advanced.AdvancedScanRequest req)
    {
        var adapter = string.IsNullOrWhiteSpace(req.InterfaceId) ? null : _net.Find(req.InterfaceId!);
        return Advanced.AdvancedScanValidator.Build(req, adapter, Advanced.AdvancedScanValidator.ResolveHost, _catalog.Get("standard")?.Ports);
    }

    public async Task<(string ScanId, bool Existing)> StartAdvancedAsync(Advanced.AdvancedScanRequest req, string? idempotencyKey)
    {
        if (_db.MigrationFailed) throw new ApiException(503, "MIGRATION_FAILED");
        var plan = BuildAdvancedPlan(req);
        var adapter = string.IsNullOrWhiteSpace(req.InterfaceId) ? null : _net.Find(req.InterfaceId!);
        var key = string.IsNullOrWhiteSpace(idempotencyKey) ? null : idempotencyKey.Trim();
        if (key is { Length: > 128 }) throw new ApiException(400, "IDEMPOTENCY_KEY_INVALID");
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"adv|{req.InterfaceId}|{plan.Technique}|{string.Join(',', plan.IpTargets)}|{string.Join(',', plan.TcpPorts)}|{string.Join(',', plan.UdpPorts)}|{plan.OsDetection}|{plan.Traceroute}|{plan.ReverseDns}|{plan.ServiceChecks}|{plan.ServiceVersion}")));

        lock (_gate)
        {
            if (key is not null && _idempotency.TryGetValue(key, out var prior))
            {
                if (prior.Hash == hash) return (prior.ScanId, true);
                throw new ApiException(409, "IDEMPOTENCY_CONFLICT");
            }
            if (_starting || (_active is not null && ScanStates.IsActive(_active.State)))
                throw new ApiException(409, "SCAN_ACTIVE", new { scan_id = _active?.Id });
            _starting = true;
        }
        try
        {
            var id = Guid.NewGuid().ToString();
            var engineVersion = $"lanora-advanced-{AppVersion}";
            var summary = new
            {
                engine = "advanced",
                method = "advanced",
                technique = plan.Technique.ToString().ToLowerInvariant(),
                include_udp = plan.IncludeUdp,
                port_scope = req.PortScope,
                tcp_port_count = plan.TcpPorts.Count,
                udp_port_count = plan.UdpPorts.Count,
                // Real port lists for comparison (as compressed ranges if very large).
                tcp_ports = CompactPorts(plan.TcpPorts),
                udp_ports = CompactPorts(plan.UdpPorts),
                service_version = req.ServiceVersion,
                os_detection = plan.OsDetection,
                traceroute = plan.Traceroute,
                reverse_dns = plan.ReverseDns,
                service_checks = plan.ServiceChecks,
                any_external = plan.AnyExternal,
            };
            var scope = await _store.CreateAdvancedScanAsync(id, plan, adapter, engineVersion, _risk.Version, summary).ConfigureAwait(false);
            var job = new Advanced.AdvancedScanJob(id, plan, scope, plan.IpTargets.Count);
            lock (_gate)
            {
                _active = job;
                if (key is not null) _idempotency[key] = (hash, id);
            }
            job.Runner = Task.Run(() => RunAdvancedAsync(job, adapter));
            AppLog.Info("scan", $"advanced scan {id} started: technique={plan.Technique} targets={plan.IpTargets.Count} external={plan.AnyExternal}");
            return (id, false);
        }
        finally
        {
            lock (_gate) _starting = false;
        }
    }

    private async Task RunAdvancedAsync(Advanced.AdvancedScanJob job, AdapterInfo? adapter)
    {
        var ct = job.Cts.Token;
        var failed = false;
        // Separate CTS for cancellation/time budget; devices found so far are kept on cancel.
        using var timeBudget = new CancellationTokenSource(TimeSpan.FromMinutes(_catalog.Rate.TimeBudgetMinutes));
        using var budgetReg = timeBudget.Token.Register(() => Abort(job, "TIME_BUDGET_EXCEEDED"));
        using var progressLoop = new CancellationTokenSource();
        var progressTask = AdvancedProgressLoopAsync(job, progressLoop.Token);
        var hosts = new List<HostResult>();  // the engine accumulates into this list; it stays filled on cancel
        var spec = BuildNativeSpec(job.Plan, adapter);

        try
        {
            job.State = ScanStates.Running;
            await _store.SetStateAsync(job.Id, ScanStates.Running).ConfigureAwait(false);
            var progress = new Progress<Native.NativeProgress>(p =>
            {
                job.Percent = p.Percent; job.PhaseLabel = PhaseLabel(p.Phase);
                job.HostsResponded = p.HostsResponded; job.OpenPorts = p.OpenPorts;
            });
            await _native.RunAsync(spec, progress, ct, hosts).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Cancel, time budget or network: devices/observations so far are saved below.
        }
        catch (Exception ex)
        {
            failed = true;
            job.StopReason ??= "ENGINE_ERROR";
            AppLog.Error("advanced", ex);
        }

        job.HostsResponded = hosts.Count;
        job.OpenPorts = hosts.Sum(h => h.Ports.Values.Count(p => p.State == PortState.Open));

        var finalState = failed ? ScanStates.Failed
            : job.UserCancelled || job.StopReason == "APP_EXIT" ? ScanStates.Cancelled
            : job.StopReason is not null ? ScanStates.Partial
            : ScanStates.Completed;

        if (finalState != ScanStates.Completed) MarkUnmeasured(job, hosts);

        try
        {
            var evaluated = new List<HostScore>();
            var hostScores = new Dictionary<string, int?>();
            foreach (var h in hosts)
            {
                var findings = _risk.Evaluate(h);
                var score = RiskEngine.ScoreHost(h, findings);
                evaluated.Add(score);
                hostScores[h.IpText] = score.Score;
                job.Findings += findings.Count(f => RiskEngine.IsPriority(f.Severity));
                await _store.SaveHostAsync(job.Id, job.ScopeId, h, findings, score).ConfigureAwait(false);
            }
            var network = RiskEngine.ScoreNetwork(evaluated, provisional: finalState != ScanStates.Completed);
            await _store.FinishScanAsync(job.Id, finalState, job.StopReason, job.HostsResponded, Interlocked.Read(ref spec.Attempts), network, hostScores, _risk.Version).ConfigureAwait(false);
            if (finalState == ScanStates.Completed) await _badges.EvaluateAsync(job.Id).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            AppLog.Error("advanced.finalize", ex);
            finalState = ScanStates.Failed;
            try { await _store.FinishScanAsync(job.Id, finalState, "SAVE_FAILED", job.HostsResponded, 0, null, new Dictionary<string, int?>(), _risk.Version).ConfigureAwait(false); }
            catch (Exception ex2) { AppLog.Error("advanced.finalize", ex2); }
        }

        job.State = finalState;
        progressLoop.Cancel();
        try { await progressTask.ConfigureAwait(false); } catch { }
        job.Events.Publish("scan_finished", new { scan_id = job.Id, state = finalState, reason_code = job.StopReason, summary = _store.GetSummary(job.Id) }, finish: true);
        AppLog.Info("scan", $"advanced scan {job.Id} finished: {finalState} {job.StopReason}");

        lock (_gate)
        {
            if (_active == job) _active = null;
            _recent.AddFirst(job);
            while (_recent.Count > 5) _recent.RemoveLast();
        }
    }

    private Native.NativeScanSpec BuildNativeSpec(Advanced.AdvancedPlan plan, AdapterInfo? adapter) => new()
    {
        Targets = plan.IpTargets,
        TcpPorts = plan.TcpPorts,
        UdpPorts = plan.UdpPorts,
        LocalIp = plan.LocalIp,
        Gateway = plan.Gateway,
        LocalMac = adapter?.Mac,
        InterfaceIndex = adapter?.InterfaceIndex ?? 0,
        TimeoutMs = 1000,
        Concurrency = _catalog.Rate.GlobalConcurrency,
        PerHostConcurrency = _catalog.Rate.PerHostConcurrency,
        RatePerSecond = _catalog.Rate.NewConnectionsPerSecond,
        ReverseDns = plan.ReverseDns,
        OsDetection = plan.OsDetection,
        ServiceVersion = plan.ServiceVersion,
        Traceroute = plan.Traceroute,
        Scripts = plan.ServiceChecks,
        IncludeVuln = false,
        TreatAllOnline = plan.AnyExternal,
    };

    /// <summary>
    /// In an unfinished advanced scan, marks planned but unmeasured ports as not_tested so that
    /// coverage and reports clearly show a partial result. Capped for very large plans to avoid bloating the database.
    /// </summary>
    private static void MarkUnmeasured(Advanced.AdvancedScanJob job, List<HostResult> hosts)
    {
        const long MaxFill = 262_144;
        var perHost = job.Plan.TcpPorts.Count + job.Plan.UdpPorts.Count;
        if ((long)perHost * hosts.Count > MaxFill)
        {
            AppLog.Warn("advanced", $"unmeasured ports not expanded ({hosts.Count} hosts x {perHost} ports)");
            return;
        }
        var reason = job.StopReason switch
        {
            "USER_CANCELLED" or "APP_EXIT" => "cancelled",
            "TIME_BUDGET_EXCEEDED" => "time_budget",
            "ENGINE_ERROR" => "engine_error",
            _ => "not_attempted",
        };
        foreach (var h in hosts)
        {
            foreach (var p in job.Plan.TcpPorts)
                if (!h.Ports.ContainsKey(p))
                    h.Ports[p] = new PortObservationResult { Protocol = "tcp", Port = p, State = PortState.NotTested, ReasonCode = reason, Method = "tcp_connect" };
            foreach (var p in job.Plan.UdpPorts)
                if (!h.Ports.ContainsKey(-p))
                    h.Ports[-p] = new PortObservationResult { Protocol = "udp", Port = p, State = PortState.NotTested, ReasonCode = reason, Method = "udp_probe" };
        }
    }

    /// <summary>Compresses a port list into the form "22,80,8000-8010" (limits snapshot size).</summary>
    internal static string CompactPorts(IReadOnlyList<int> ports)
    {
        if (ports.Count == 0) return "";
        var sorted = ports.Distinct().Order().ToList();
        var parts = new List<string>();
        var start = sorted[0];
        var prev = start;
        foreach (var p in sorted.Skip(1).Append(int.MaxValue))
        {
            if (p == prev + 1) { prev = p; continue; }
            parts.Add(start == prev ? start.ToString() : $"{start}-{prev}");
            start = prev = p;
        }
        return string.Join(',', parts);
    }

    private static string PhaseLabel(string phase) => phase switch
    {
        "discovery" => "Discovery",
        "port_scan" => "Port scan",
        "enrichment" => "Services and checks",
        "scoring" => "Assessment",
        _ => phase,
    };

    private async Task AdvancedProgressLoopAsync(Advanced.AdvancedScanJob job, CancellationToken ct)
    {
        string? last = null;
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(600, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            var p = job.Progress();
            var s = Json.Serialize(p);
            if (s != last) job.Events.Publish("progress", p);
            last = s;
        }
    }

    // ---------- Start / cancel ----------

    public async Task<(string ScanId, bool Existing)> StartAsync(ScanRequest req, string? idempotencyKey)
    {
        if (_db.MigrationFailed) throw new ApiException(503, "MIGRATION_FAILED");
        var plan = BuildPlan(req);
        var hash = PlanHash(plan);
        var key = string.IsNullOrWhiteSpace(idempotencyKey) ? null : idempotencyKey.Trim();
        if (key is { Length: > 128 }) throw new ApiException(400, "IDEMPOTENCY_KEY_INVALID");

        lock (_gate)
        {
            if (key is not null && _idempotency.TryGetValue(key, out var prior))
            {
                if (prior.Hash == hash) return (prior.ScanId, true);
                throw new ApiException(409, "IDEMPOTENCY_CONFLICT");
            }
            if (_starting || (_active is not null && ScanStates.IsActive(_active.State)))
                throw new ApiException(409, "SCAN_ACTIVE", new { scan_id = _active?.Id });
            _starting = true;
        }

        try
        {
            var id = Guid.NewGuid().ToString();
            var scope = await _store.CreateScanAsync(id, plan, EngineVersion, _risk.Version).ConfigureAwait(false);
            var job = new ScanJob(id, plan, scope);
            lock (_gate)
            {
                _active = job;
                if (key is not null) _idempotency[key] = (hash, id);
            }
            job.Runner = Task.Run(() => RunAsync(job));
            AppLog.Info("scan", $"scan {id} started: profile={plan.ProfileId} targets={plan.Targets.Targets.Count} ports={plan.Ports.Count}");
            return (id, false);
        }
        finally
        {
            lock (_gate) _starting = false;
        }
    }

    /// <summary>Cancel stops new probes; results already received are kept. Repeating it is idempotent.</summary>
    public bool Cancel(string scanId)
    {
        IScanJob? job;
        lock (_gate) job = _active?.Id == scanId ? _active : null;
        if (job is null) return _store.GetSummary(scanId) is not null;
        if (!ScanStates.IsActive(job.State)) return true;
        job.UserCancelled = true;
        job.StopReason ??= "USER_CANCELLED";
        job.State = ScanStates.Cancelling;
        job.Events.Publish("phase_changed", job.Progress());
        _ = _store.SetStateAsync(job.Id, ScanStates.Cancelling);
        job.Cts.Cancel();
        return true;
    }

    public async Task ShutdownAsync()
    {
        IScanJob? job;
        lock (_gate) job = _active;
        if (job?.Runner is null || !ScanStates.IsActive(job.State)) return;
        Abort(job, "APP_EXIT");
        await Task.WhenAny(job.Runner, Task.Delay(TimeSpan.FromSeconds(8))).ConfigureAwait(false);
    }

    private static void Abort(IScanJob job, string reason)
    {
        if (job.Cts.IsCancellationRequested) return;
        job.StopReason ??= reason;
        try { job.Cts.Cancel(); } catch (ObjectDisposedException) { }
    }

    // ---------- Execution ----------

    private async Task RunAsync(ScanJob job)
    {
        var ct = job.Cts.Token;
        var plan = job.Plan;
        var hosts = new Dictionary<uint, HostResult>();
        var rate = new RateLimiter(plan.Rate.NewConnectionsPerSecond);
        var failed = false;

        using var timeBudget = new CancellationTokenSource(TimeSpan.FromMinutes(plan.Rate.TimeBudgetMinutes));
        using var budgetReg = timeBudget.Token.Register(() => Abort(job, "TIME_BUDGET_EXCEEDED"));
        NetworkAddressChangedEventHandler netHandler = (_, _) => CheckNetwork(job);
        NetworkAvailabilityChangedEventHandler availHandler = (_, e) => { if (!e.IsAvailable) Abort(job, "NETWORK_CHANGED"); };
        NetworkChange.NetworkAddressChanged += netHandler;
        NetworkChange.NetworkAvailabilityChanged += availHandler;
        using var progressLoop = new CancellationTokenSource();
        var progressTask = ProgressLoopAsync(job, progressLoop.Token);

        try
        {
            job.State = ScanStates.Running;
            await _store.SetStateAsync(job.Id, ScanStates.Running).ConfigureAwait(false);
            await DiscoveryAsync(job, hosts, rate, ct).ConfigureAwait(false);
            var alive = hosts.Values.Where(h => h.Alive).OrderBy(h => h.Ip).ToList();
            job.HostsResponded = alive.Count;
            foreach (var h in alive)
                foreach (var p in plan.Ports)
                    h.Ports[p] = new PortObservationResult { Protocol = "tcp", Port = p };
            await PortScanAsync(job, alive, rate, ct).ConfigureAwait(false);
            await EnrichAsync(job, alive, rate, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Cancel, budget or network change; results are saved below.
        }
        catch (Exception ex)
        {
            failed = true;
            job.StopReason ??= "ENGINE_ERROR";
            AppLog.Error("scan", ex);
        }
        finally
        {
            NetworkChange.NetworkAddressChanged -= netHandler;
            NetworkChange.NetworkAvailabilityChanged -= availHandler;
        }

        var finalState = failed ? ScanStates.Failed
            : job.UserCancelled || job.StopReason == "APP_EXIT" ? ScanStates.Cancelled
            : job.StopReason is not null ? ScanStates.Partial
            : ScanStates.Completed;

        try
        {
            await FinalizeAsync(job, hosts, finalState).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            AppLog.Error("scan.finalize", ex);
            finalState = ScanStates.Failed;
            try { await _store.FinishScanAsync(job.Id, finalState, "SAVE_FAILED", job.HostsResponded, job.Attempts, null, new Dictionary<string, int?>(), _risk.Version).ConfigureAwait(false); }
            catch (Exception ex2) { AppLog.Error("scan.finalize", ex2); }
        }

        job.State = finalState;
        progressLoop.Cancel();
        try { await progressTask.ConfigureAwait(false); } catch { }
        job.Events.Publish("scan_finished", new { scan_id = job.Id, state = finalState, reason_code = job.StopReason, summary = _store.GetSummary(job.Id) }, finish: true);
        AppLog.Info("scan", $"scan {job.Id} finished: {finalState} {job.StopReason}");

        lock (_gate)
        {
            if (_active == job) _active = null;
            _recent.AddFirst(job);
            while (_recent.Count > 5) _recent.RemoveLast();
        }
    }

    private async Task ProgressLoopAsync(ScanJob job, CancellationToken ct)
    {
        string? last = null;
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(500, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            var p = job.Progress();
            var s = Json.Serialize(p);
            if (s != last) job.Events.Publish("progress", p);
            last = s;
        }
    }

    private void SetPhase(ScanJob job, string phase, long total)
    {
        job.Phase = phase;
        Interlocked.Exchange(ref job.PhaseTotal, total);
        Interlocked.Exchange(ref job.PhaseDone, 0);
        job.Events.Publish("phase_changed", job.Progress());
    }

    private void CheckNetwork(ScanJob job)
    {
        try
        {
            var current = _net.Find(job.Plan.Adapter.Id);
            if (current is null || current.Ip != job.Plan.Adapter.Ip || current.PrefixLength != job.Plan.Adapter.PrefixLength)
                Abort(job, "NETWORK_CHANGED");
        }
        catch (Exception ex)
        {
            AppLog.Warn("scan", "network check failed: " + ex.Message);
        }
    }

    // ---------- Phase 1: discovery (FR03) ----------

    private async Task DiscoveryAsync(ScanJob job, Dictionary<uint, HostResult> hosts, RateLimiter rate, CancellationToken ct)
    {
        var plan = job.Plan;
        SetPhase(job, Phases.Discovery, plan.Targets.Targets.Count);
        foreach (var ip in plan.Targets.Targets)
        {
            var h = new HostResult { Ip = ip, IsLocal = ip == plan.Targets.LocalIp, IsGateway = plan.Targets.Gateway == ip };
            if (h.IsLocal)
            {
                h.DiscoveryEvidence.Add("local");
                h.Mac = plan.Adapter.Mac;
                h.MacSource = "local_adapter";
            }
            hosts[ip] = h;
        }

        // ICMP echo: no reply is never turned into a conclusion that the device is offline.
        await Parallel.ForEachAsync(hosts.Values.Where(h => !h.IsLocal),
            new ParallelOptions { MaxDegreeOfParallelism = plan.Rate.GlobalConcurrency, CancellationToken = ct },
            async (h, token) =>
            {
                var (reply, ttl) = await _backend.PingAsync(h.Ip, IcmpTimeoutMs, token).ConfigureAwait(false);
                if (reply)
                {
                    lock (h) { h.DiscoveryEvidence.Add("icmp"); h.IcmpTtl = ttl; }
                }
                Interlocked.Increment(ref job.PhaseDone);
            }).ConfigureAwait(false);

        await Task.Delay(300, ct).ConfigureAwait(false);
        var neighbors = ReadNeighbors(plan.Adapter.InterfaceIndex);
        ApplyNeighbors(hosts, neighbors, markReachable: true);

        // Limited TCP reachability evidence: only addresses without ICMP/ARP evidence whose ARP resolution did not visibly fail.
        var candidates = hosts.Values.Where(h => !h.Alive && (neighbors is null ||
            (neighbors.TryGetValue(h.Ip, out var n) && n.State is not (NeighborState.Unreachable or NeighborState.Incomplete)))).ToList();
        Interlocked.Add(ref job.PhaseTotal, candidates.Count * DiscoveryPorts.Length);
        await Parallel.ForEachAsync(candidates,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, plan.Rate.GlobalConcurrency / 4), CancellationToken = ct },
            async (h, token) =>
            {
                foreach (var port in DiscoveryPorts)
                {
                    if (Interlocked.Increment(ref job.Attempts) > plan.MaxAttempts)
                    {
                        Interlocked.Decrement(ref job.Attempts);
                        Abort(job, "ATTEMPT_BUDGET_EXCEEDED");
                        token.ThrowIfCancellationRequested();
                    }
                    await rate.WaitAsync(token).ConfigureAwait(false);
                    var r = await _backend.ProbeTcpAsync(h.Ip, port, DiscoveryTcpTimeoutMs, token).ConfigureAwait(false);
                    Interlocked.Increment(ref job.PhaseDone);
                    if (r.State is PortState.Open or PortState.Closed)
                    {
                        lock (h) h.DiscoveryEvidence.Add("tcp");
                        break;
                    }
                }
            }).ConfigureAwait(false);

        if (candidates.Count > 0) ApplyNeighbors(hosts, ReadNeighbors(plan.Adapter.InterfaceIndex), markReachable: false);

        foreach (var h in hosts.Values.Where(h => h.Alive).OrderBy(h => h.Ip))
        {
            h.Vendor = _oui.Lookup(h.Mac);
            job.Events.Publish("host_observed", new
            {
                ip = h.IpText, evidence = h.DiscoveryEvidence.Order().ToArray(), mac = h.Mac, vendor = h.Vendor,
                is_local = h.IsLocal, is_gateway = h.IsGateway,
            });
        }
        job.HostsResponded = hosts.Values.Count(h => h.Alive);
    }

    private static Dictionary<uint, NeighborEntry>? ReadNeighbors(uint ifIndex)
    {
        try
        {
            return NativeMethods.GetNeighbors().Where(n => n.InterfaceIndex == ifIndex)
                .GroupBy(n => n.Ip).ToDictionary(g => g.Key, g => g.OrderByDescending(n => n.State == NeighborState.Reachable).First());
        }
        catch (Exception ex)
        {
            AppLog.Warn("discovery", "neighbor table unavailable: " + ex.Message);
            return null;
        }
    }

    /// <summary>A stale neighbor entry alone does not make a device active: only the Reachable state counts as ARP evidence.</summary>
    private static void ApplyNeighbors(Dictionary<uint, HostResult> hosts, Dictionary<uint, NeighborEntry>? neighbors, bool markReachable)
    {
        if (neighbors is null) return;
        foreach (var (ip, n) in neighbors)
        {
            if (!hosts.TryGetValue(ip, out var h) || h.IsLocal) continue;
            if (markReachable && n.State == NeighborState.Reachable && n.Mac is not null) h.DiscoveryEvidence.Add("arp");
            if (h.Mac is null && n.Mac is not null && n.State != NeighborState.Unreachable && (h.Alive || n.State == NeighborState.Reachable))
            {
                h.Mac = n.Mac;
                h.MacSource = "arp_neighbor_table";
            }
        }
    }

    // ---------- Phase 2: port measurement (FR04/FR05) ----------

    private async Task PortScanAsync(ScanJob job, List<HostResult> alive, RateLimiter rate, CancellationToken ct)
    {
        var plan = job.Plan;
        // Port-first ordering spreads the load across devices.
        var pairs = plan.Ports.SelectMany(p => alive.Select(h => (Host: h, Port: p))).ToList();
        SetPhase(job, Phases.PortScan, pairs.Count);
        var perHost = alive.ToDictionary(h => h.Ip, _ => new SemaphoreSlim(plan.Rate.PerHostConcurrency));
        try
        {
            await Parallel.ForEachAsync(pairs,
                new ParallelOptions { MaxDegreeOfParallelism = plan.Rate.GlobalConcurrency, CancellationToken = ct },
                async (pair, token) =>
                {
                    var sem = perHost[pair.Host.Ip];
                    await sem.WaitAsync(token).ConfigureAwait(false);
                    try
                    {
                        var obs = pair.Host.Ports[pair.Port];
                        for (var attempt = 0; attempt <= plan.Retries; attempt++)
                        {
                            if (Interlocked.Increment(ref job.Attempts) > plan.MaxAttempts)
                            {
                                Interlocked.Decrement(ref job.Attempts);
                                if (obs.Attempts == 0) obs.ReasonCode = "attempt_budget";
                                Abort(job, "ATTEMPT_BUDGET_EXCEEDED");
                                return;
                            }
                            await rate.WaitAsync(token).ConfigureAwait(false);
                            var r = await _backend.ProbeTcpAsync(pair.Host.Ip, pair.Port, plan.TimeoutMs, token).ConfigureAwait(false);
                            obs.State = r.State;
                            obs.ReasonCode = r.ReasonCode;
                            obs.Attempts++;
                            obs.ObservedAt = DateTimeOffset.UtcNow;
                            if (r.State != PortState.NoResponse) break;
                        }
                        if (obs.State == PortState.Open)
                        {
                            Interlocked.Increment(ref job.OpenPorts);
                            job.Events.Publish("port_observed", new { ip = pair.Host.IpText, protocol = obs.Protocol, port = obs.Port, state = obs.State, method = obs.Method });
                        }
                    }
                    finally
                    {
                        sem.Release();
                        Interlocked.Increment(ref job.PhaseDone);
                    }
                }).ConfigureAwait(false);
        }
        finally
        {
            foreach (var s in perHost.Values) s.Dispose();
        }
    }

    // ---------- Phase 3: enrichment (FR11) ----------

    private async Task EnrichAsync(ScanJob job, List<HostResult> alive, RateLimiter rate, CancellationToken ct)
    {
        var open = alive.SelectMany(h => h.Ports.Values.Where(o => o.State == PortState.Open).Select(o => (Host: h, Obs: o))).ToList();
        SetPhase(job, Phases.Enrichment, open.Count);
        var perHost = alive.ToDictionary(h => h.Ip, _ => new SemaphoreSlim(2));
        try
        {
            await Parallel.ForEachAsync(open, new ParallelOptions { MaxDegreeOfParallelism = 16, CancellationToken = ct }, async (item, token) =>
            {
                try
                {
                    if (!ServiceProber.HasProbe(item.Obs.Port))
                    {
                        item.Obs.Service = new ServiceEvidence { ServiceName = PortCatalog.ServiceName(item.Obs.Port) };
                        return;
                    }
                    var sem = perHost[item.Host.Ip];
                    await sem.WaitAsync(token).ConfigureAwait(false);
                    try
                    {
                        await rate.WaitAsync(token).ConfigureAwait(false);
                        item.Obs.Service = await _prober.ProbeAsync(item.Host.Ip, item.Obs.Port, token).ConfigureAwait(false);
                    }
                    finally
                    {
                        sem.Release();
                    }
                }
                finally
                {
                    Interlocked.Increment(ref job.PhaseDone);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            foreach (var s in perHost.Values) s.Dispose();
        }
    }

    // ---------- Phases 4-5: scoring and persistence ----------

    private async Task FinalizeAsync(ScanJob job, Dictionary<uint, HostResult> hosts, string finalState)
    {
        var alive = hosts.Values.Where(h => h.Alive).OrderBy(h => h.Ip).ToList();
        var notTestedReason = job.StopReason switch
        {
            "USER_CANCELLED" or "APP_EXIT" => "cancelled",
            "TIME_BUDGET_EXCEEDED" => "time_budget",
            "ATTEMPT_BUDGET_EXCEEDED" => "attempt_budget",
            "NETWORK_CHANGED" => "network_changed",
            "ENGINE_ERROR" => "engine_error",
            _ => "not_attempted",
        };
        foreach (var h in alive)
        {
            foreach (var p in job.Plan.Ports)
            {
                if (!h.Ports.TryGetValue(p, out var o)) h.Ports[p] = o = new PortObservationResult { Protocol = "tcp", Port = p };
                if (o.Attempts == 0 && o.State == PortState.NotTested && o.ReasonCode == "not_attempted") o.ReasonCode = notTestedReason;
            }
        }

        SetPhase(job, Phases.Scoring, alive.Count);
        var evaluated = new List<(HostResult Host, IReadOnlyList<FindingResult> Findings, HostScore Score)>();
        foreach (var h in alive)
        {
            HostClassifier.Classify(h);
            var findings = _risk.Evaluate(h);
            var score = RiskEngine.ScoreHost(h, findings);
            evaluated.Add((h, findings, score));
            foreach (var f in findings.Where(f => RiskEngine.IsPriority(f.Severity)))
            {
                Interlocked.Increment(ref job.Findings);
                job.Events.Publish("finding_added", new { ip = h.IpText, port = f.Port, protocol = f.Protocol, rule_id = f.RuleId, severity = f.Severity });
            }
            Interlocked.Increment(ref job.PhaseDone);
        }
        var network = RiskEngine.ScoreNetwork(evaluated.Select(e => e.Score).ToList(), provisional: finalState != ScanStates.Completed);

        SetPhase(job, Phases.Saving, evaluated.Count + 1);
        foreach (var (h, findings, score) in evaluated)
        {
            await _store.SaveHostAsync(job.Id, job.ScopeId, h, findings, score).ConfigureAwait(false);
            Interlocked.Increment(ref job.PhaseDone);
        }
        await _store.FinishScanAsync(job.Id, finalState, job.StopReason is "USER_CANCELLED" ? "USER_CANCELLED" : job.StopReason, job.HostsResponded,
            Interlocked.Read(ref job.Attempts), network, evaluated.ToDictionary(e => e.Host.IpText, e => e.Score.Score), _risk.Version).ConfigureAwait(false);
        if (finalState == ScanStates.Completed) await _badges.EvaluateAsync(job.Id).ConfigureAwait(false);
        Interlocked.Increment(ref job.PhaseDone);
    }
}
