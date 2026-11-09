using System.Text;
using System.Text.Json;
using Lanora.Data;
using Lanora.Infrastructure;
using Lanora.Net;
using Lanora.Risk;
using Lanora.Scanning;

namespace Lanora.Cli;

/// <summary>What the command line needs from the machine; tests replace the network and the scan backend.</summary>
internal sealed record CliEnvironment(AppPaths Paths, NetworkInfoService Network, IScanBackend Backend, PortCatalog Catalog)
{
    public static CliEnvironment Default(string? dataDir) =>
        new(new AppPaths(dataDir), new NetworkInfoService(), new SocketBackend(), new PortCatalog());
}

/// <summary>
/// Runs a command line request in-process with the same engine, rules and database as the window app.
/// Results go to stdout, progress and errors to stderr; a "cancel" line on stdin cancels a running scan.
/// </summary>
internal sealed class CliRunner
{
    public const int ExitOk = 0, ExitError = 1, ExitUsage = 2, ExitFindings = 3, ExitIncomplete = 4;

    private readonly TextWriter _out;
    private readonly TextWriter _err;
    private readonly TextReader? _in;
    private readonly Func<string?, CliEnvironment> _environment;

    public CliRunner(TextWriter stdout, TextWriter stderr, TextReader? stdin, Func<string?, CliEnvironment>? environment = null)
    {
        _out = stdout;
        _err = stderr;
        _in = stdin;
        _environment = environment ?? CliEnvironment.Default;
    }

    /// <summary>Entry point used by Program for <c>Lanora.exe --cli ...</c>.</summary>
    public static int RunConsole(string[] args)
    {
        var utf8 = new UTF8Encoding(false);
        using var stdout = new StreamWriter(Console.OpenStandardOutput(), utf8) { AutoFlush = true };
        using var stderr = new StreamWriter(Console.OpenStandardError(), utf8) { AutoFlush = true };
        // stdin is deliberately not disposed: a background read for "cancel" may still be pending when the command ends,
        // and disposing a pipe stream under a pending read can block the exit.
        var stdin = new StreamReader(Console.OpenStandardInput(), utf8);
        return new CliRunner(stdout, stderr, stdin).RunAsync(args).GetAwaiter().GetResult();
    }

    public async Task<int> RunAsync(IReadOnlyList<string> args)
    {
        var opts = CliOptions.Parse(args);
        if (opts.Error is not null)
        {
            await _err.WriteLineAsync("lanora: " + opts.Error).ConfigureAwait(false);
            return ExitUsage;
        }
        switch (opts.Command)
        {
            case "help":
                await _out.WriteLineAsync(CliOptions.Usage).ConfigureAwait(false);
                return ExitOk;
            case "version":
                await _out.WriteLineAsync("LANORA " + ScanOrchestrator.AppVersion).ConfigureAwait(false);
                return ExitOk;
        }

        CliEnvironment env;
        try { env = _environment(opts.DataDir); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            await _err.WriteLineAsync("lanora: the data folder cannot be used: " + ex.Message).ConfigureAwait(false);
            return ExitError;
        }
        AppLog.Init(env.Paths.Logs);

        try
        {
            if (opts.Command == "interfaces") return await InterfacesAsync(env, opts).ConfigureAwait(false);

            var db = new Database(env.Paths);
            db.Initialize();
            try
            {
                if (db.MigrationFailed)
                {
                    await _err.WriteLineAsync("lanora: the database could not be upgraded; details are in " + env.Paths.Logs).ConfigureAwait(false);
                    return ExitError;
                }
                var store = new ScanStore(db);
                return opts.Command switch
                {
                    "scan" => await ScanAsync(env, db, store, opts).ConfigureAwait(false),
                    "history" => await HistoryAsync(store, opts).ConfigureAwait(false),
                    "show" => await ShowAsync(store, opts).ConfigureAwait(false),
                    _ => ExitUsage,
                };
            }
            finally
            {
                db.Dispose();
            }
        }
        catch (ApiException ex)
        {
            await _err.WriteLineAsync("lanora: " + CliText.Error(ex)).ConfigureAwait(false);
            return ex.Status is 400 or 403 ? ExitUsage : ExitError;
        }
        catch (Exception ex)
        {
            AppLog.Error("cli", ex);
            await _err.WriteLineAsync($"lanora: unexpected error ({ex.GetType().Name}); details are in {env.Paths.Logs}").ConfigureAwait(false);
            return ExitError;
        }
    }

    // ---------------- interfaces ----------------

    private async Task<int> InterfacesAsync(CliEnvironment env, CliOptions opts)
    {
        var adapters = env.Network.GetAdapters();
        if (opts.Format == "json")
        {
            await _out.WriteLineAsync(Json.Serialize(new { items = adapters })).ConfigureAwait(false);
            return ExitOk;
        }
        if (opts.Format == "csv")
        {
            var csv = new StringBuilder("id,name,kind,ip,network,gateway,mac,default_route,selectable,not_selectable_reason,suggested_range\r\n");
            foreach (var a in adapters)
                Csv.Row(csv, a.Id, a.Name, a.Kind, a.Ip, a.NetworkCidr, a.Gateway, a.Mac, a.IsDefaultRoute ? "yes" : "no", a.Selectable ? "yes" : "no", a.NotSelectableReason, a.SuggestedRange);
            await _out.WriteAsync(csv.ToString()).ConfigureAwait(false);
            return ExitOk;
        }
        if (adapters.Count == 0)
        {
            await _out.WriteLineAsync("No IPv4 network adapter is connected.").ConfigureAwait(false);
            return ExitOk;
        }
        var rows = adapters.Select(a => new[]
        {
            a.Name + (a.IsDefaultRoute ? " *" : ""), a.Kind, $"{a.Ip}/{a.PrefixLength}", a.Gateway ?? "—",
            a.Selectable ? a.SuggestedRange ?? a.NetworkCidr : "not scannable: " + (a.NotSelectableReason ?? "?"),
        }).ToList();
        await _out.WriteAsync(CliText.Table(new[] { "Adapter", "Kind", "Address", "Gateway", "Scan range" }, rows)).ConfigureAwait(false);
        await _out.WriteLineAsync("* default route. Use --interface <name or address> to choose an adapter.").ConfigureAwait(false);
        return ExitOk;
    }

    // ---------------- scan ----------------

    private async Task<int> ScanAsync(CliEnvironment env, Database db, ScanStore store, CliOptions opts)
    {
        var adapters = env.Network.GetAdapters();
        var (adapter, problem) = SelectAdapter(adapters, opts);
        if (adapter is null)
        {
            await _err.WriteLineAsync("lanora: " + problem).ConfigureAwait(false);
            return ExitUsage;
        }

        var settings = new SettingsStore(db);
        var profile = opts.Profile ?? settings.Get().DefaultProfile;
        if (profile == "custom" && opts.Ports is null) profile = "quick"; // the saved default needs a port list the CLI does not have
        var targets = opts.Targets.Count > 0 ? opts.Targets : new List<string> { adapter.SuggestedRange ?? adapter.NetworkCidr };

        var rules = new Ruleset();
        var risk = new RiskEngine(rules);
        var orch = new ScanOrchestrator(env.Network, env.Catalog, risk, store, new BadgeService(db), new OuiDatabase(), env.Backend, new ServiceProber(), db);
        var (id, _) = await orch.StartAsync(new ScanRequest { InterfaceId = adapter.Id, Targets = targets, ProfileId = profile, TcpPorts = opts.Ports }, null)
            .ConfigureAwait(false);
        var job = orch.GetJob(id)!;

        if (opts.Format == "text")
            await _err.WriteLineAsync($"Scanning {string.Join(", ", targets)} from {adapter.Name} ({adapter.Ip}), profile {profile}. Press Ctrl+C to cancel.")
                .ConfigureAwait(false);

        using var stopWatching = new CancellationTokenSource();
        var watcher = WatchForCancelAsync(orch, id, stopWatching.Token);
        var lastLine = 0;
        while (!job.Runner!.IsCompleted)
        {
            if (opts.Progress) lastLine = await ProgressAsync(job, lastLine).ConfigureAwait(false);
            await Task.WhenAny(job.Runner, Task.Delay(500)).ConfigureAwait(false);
        }
        await job.Runner.ConfigureAwait(false);
        stopWatching.Cancel();
        if (lastLine > 0) await _err.WriteAsync("\r" + new string(' ', lastLine) + "\r").ConfigureAwait(false);
        _ = watcher; // reading stdin cannot be interrupted; the task ends with the process

        var summary = store.GetSummary(id)!;
        var hosts = store.GetHosts(id);
        await PrintScanAsync(summary, hosts, rules, opts.Format).ConfigureAwait(false);
        return ExitCode(summary, hosts, opts.FailOn);
    }

    internal static (AdapterInfo? Adapter, string? Problem) SelectAdapter(IReadOnlyList<AdapterInfo> adapters, CliOptions opts)
    {
        var selectable = adapters.Where(a => a.Selectable).ToList();
        if (opts.Interface is { } wanted)
        {
            var match = adapters.FirstOrDefault(a => a.Id == wanted)
                ?? adapters.FirstOrDefault(a => a.Ip == wanted)
                ?? adapters.FirstOrDefault(a => string.Equals(a.Name, wanted, StringComparison.OrdinalIgnoreCase));
            if (match is null) return (null, $"No adapter \"{wanted}\". Run \"lanora interfaces\".");
            if (!match.Selectable) return (null, $"Adapter \"{match.Name}\" cannot be scanned: {match.NotSelectableReason}.");
            return (match, null);
        }
        if (selectable.Count == 0) return (null, "No adapter of a private local network can be scanned. Run \"lanora interfaces\".");

        // The adapter whose network contains the first target, otherwise the default route.
        var first = opts.Targets.Select(FirstAddress).FirstOrDefault(ip => ip is not null);
        if (first is { } ip)
        {
            var owner = selectable.FirstOrDefault(a => a.Network.Contains(ip));
            if (owner is not null) return (owner, null);
        }
        var chosen = selectable.FirstOrDefault(a => a.IsDefaultRoute) ?? (selectable.Count == 1 ? selectable[0] : null);
        return chosen is null
            ? (null, "Several adapters can be scanned; choose one with --interface (see \"lanora interfaces\").")
            : (chosen, null);
    }

    private static uint? FirstAddress(string target)
    {
        var end = target.IndexOfAny(new[] { '/', '-' });
        return Ipv4.TryParse(end > 0 ? target[..end] : target, out var ip) ? ip : null;
    }

    private async Task WatchForCancelAsync(ScanOrchestrator orch, string scanId, CancellationToken stop)
    {
        if (_in is null) return;
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var line = await _in.ReadLineAsync(stop).ConfigureAwait(false);
                if (line is null) return; // stdin closed
                if (line.Trim() == "cancel")
                {
                    if (orch.Cancel(scanId)) await _err.WriteLineAsync("\rCancelling… results found so far are kept.").ConfigureAwait(false);
                    return;
                }
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or ObjectDisposedException)
        {
        }
    }

    private async Task<int> ProgressAsync(IScanJob job, int previousLength)
    {
        var p = JsonSerializer.SerializeToElement(job.Progress(), Json.Options);
        string S(string n) => p.TryGetProperty(n, out var v) ? v.ToString() : "";
        var line = $"[{S("phase_index")}/{S("phase_count")}] {CliText.Phase(S("phase"))} {S("phase_percent")}%  devices {S("hosts_responded")}  open ports {S("open_ports")}";
        await _err.WriteAsync("\r" + line.PadRight(previousLength)).ConfigureAwait(false);
        return line.Length;
    }

    internal static int ExitCode(ScanSummary summary, IReadOnlyList<HostDto> hosts, string? failOn)
    {
        if (summary.State != ScanStates.Completed) return ExitIncomplete;
        if (failOn is null) return ExitOk;
        var levels = failOn == "high" ? new[] { "high" } : new[] { "high", "medium" };
        return hosts.Any(h => h.Findings.Any(f => levels.Contains(f.Severity) && !f.Required)) ? ExitFindings : ExitOk;
    }

    // ---------------- history / show ----------------

    private async Task<int> HistoryAsync(ScanStore store, CliOptions opts)
    {
        var (items, total) = store.ListScans(null, null, null, 1, opts.Limit);
        if (opts.Format == "json")
        {
            await _out.WriteLineAsync(Json.Serialize(new { items, total })).ConfigureAwait(false);
            return ExitOk;
        }
        if (opts.Format == "csv")
        {
            var csv = new StringBuilder("scan_id,started_at,state,network,profile,devices,open_ports,priority_findings,score\r\n");
            foreach (var s in items)
                Csv.Row(csv, s.Id, s.StartedAt, s.State, s.NetworkCidr, s.ProfileId, s.HostsResponded.ToString(), s.OpenPorts.ToString(), s.PriorityFindings.ToString(), s.NetworkScore?.ToString());
            await _out.WriteAsync(csv.ToString()).ConfigureAwait(false);
            return ExitOk;
        }
        if (items.Count == 0)
        {
            await _out.WriteLineAsync("No saved scans yet. Start one with \"lanora scan\".").ConfigureAwait(false);
            return ExitOk;
        }
        var rows = items.Select(s => new[]
        {
            s.Id[..8], CliText.LocalTime(s.StartedAt), s.State, s.NetworkCidr, s.ProfileId, s.HostsResponded.ToString(),
            s.OpenPorts.ToString(), s.PriorityFindings.ToString(), s.NetworkScore?.ToString() ?? "—",
        }).ToList();
        await _out.WriteAsync(CliText.Table(new[] { "Scan", "Started", "State", "Network", "Profile", "Devices", "Open", "Priority", "Score" }, rows)).ConfigureAwait(false);
        await _out.WriteLineAsync($"{items.Count} of {total} scans. Show one with \"lanora show <scan>\" (the first characters of the id are enough).").ConfigureAwait(false);
        return ExitOk;
    }

    private async Task<int> ShowAsync(ScanStore store, CliOptions opts)
    {
        var id = ResolveScanId(store, opts.ScanId!);
        if (id is null)
        {
            await _err.WriteLineAsync($"lanora: no saved scan \"{opts.ScanId}\" (or the prefix matches more than one). Run \"lanora history\".").ConfigureAwait(false);
            return ExitError;
        }
        var summary = store.GetSummary(id)!;
        var hosts = store.GetHosts(id);
        await PrintScanAsync(summary, hosts, new Ruleset(), opts.Format).ConfigureAwait(false);
        return ExitOk;
    }

    /// <summary>Full id, or a unique prefix of at least 4 characters (the short id that "history" prints).</summary>
    internal static string? ResolveScanId(ScanStore store, string value)
    {
        if (store.GetSummary(value) is not null) return value;
        if (value.Length < 4) return null;
        var matches = new List<string>();
        for (var page = 1; ; page++)
        {
            var (items, total) = store.ListScans(null, null, null, page, 100);
            matches.AddRange(items.Where(s => s.Id.StartsWith(value, StringComparison.OrdinalIgnoreCase)).Select(s => s.Id));
            if (matches.Count > 1 || page * 100 >= total) break;
        }
        return matches.Count == 1 ? matches[0] : null;
    }

    // ---------------- output ----------------

    private async Task PrintScanAsync(ScanSummary summary, IReadOnlyList<HostDto> hosts, Ruleset rules, string format)
    {
        switch (format)
        {
            case "json":
                await _out.WriteLineAsync(Json.Serialize(new { app_version = ScanOrchestrator.AppVersion, scan = summary, hosts })).ConfigureAwait(false);
                break;
            case "csv":
                await _out.WriteAsync(CliText.ScanCsv(summary, hosts)).ConfigureAwait(false);
                break;
            default:
                await _out.WriteAsync(CliText.ScanText(summary, hosts, rules)).ConfigureAwait(false);
                break;
        }
    }
}
