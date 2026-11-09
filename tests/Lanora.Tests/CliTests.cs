using System.Text.Json;
using Lanora.Cli;
using Lanora.Data;
using Lanora.Infrastructure;
using Lanora.Net;
using Lanora.Scanning;

namespace Lanora.Tests;

/// <summary>Command line ("lanora ...") tests: parsing, output formats, exit codes, cancellation and shared-database safety.</summary>
public class CliTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lanora-cli-" + Guid.NewGuid().ToString("N"));
    // Never the real ExitRequest name: setting that would close a LANORA running on the developer's machine.
    private readonly string _exitEvent = @"Local\Lanora.Test.ExitRequest." + Guid.NewGuid().ToString("N");

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { }
    }

    /// <summary>A fixed adapter instead of the machine's real network.</summary>
    private sealed class FakeNetwork(params AdapterInfo[] adapters) : NetworkInfoService
    {
        public override IReadOnlyList<AdapterInfo> GetAdapters() => adapters;
    }

    /// <summary>192.168.77.20 answers ping and has 445/tcp open; other addresses stay silent.</summary>
    private sealed class FakeBackend : IScanBackend
    {
        public Func<int, CancellationToken, Task>? BeforeProbe { get; init; }
        public string Name => "fake";
        public string Version => "fake-1";

        public async Task<ProbeResult> ProbeTcpAsync(uint ip, int port, int timeoutMs, CancellationToken ct)
        {
            if (BeforeProbe is not null) await BeforeProbe(port, ct);
            if (ip != Ipv4.Parse("192.168.77.20")) return new ProbeResult(PortState.NoResponse, "timeout", 1);
            return port == 445 ? new ProbeResult(PortState.Open, "syn_ack", 1) : new ProbeResult(PortState.Closed, "conn_refused", 1);
        }

        public Task<(bool Reply, int? Ttl)> PingAsync(uint ip, int timeoutMs, CancellationToken ct) =>
            Task.FromResult((ip == Ipv4.Parse("192.168.77.20"), (int?)128));
    }

    /// <summary>stdin that sends "cancel" once the test says so.</summary>
    private sealed class CancelInput : TextReader
    {
        public readonly TaskCompletionSource Send = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override async ValueTask<string?> ReadLineAsync(CancellationToken ct)
        {
            await Send.Task.WaitAsync(ct);
            return "cancel";
        }
    }

    private static AdapterInfo Adapter() => Fixtures.Adapter("192.168.77.10", 24, "192.168.77.1") with { IsDefaultRoute = true };

    private async Task<(int Code, string Out, string Err)> Run(IScanBackend? backend = null, TextReader? stdin = null, params string[] args)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var defaults = Res.ReadJson<ProfileFile>("res/profiles.json");
        var catalog = new PortCatalog(new ProfileFile
        {
            Version = defaults.Version,
            Profiles = defaults.Profiles,
            Rate = new RateSettings { NewConnectionsPerSecond = 1000 },
        });
        var runner = new CliRunner(stdout, stderr, stdin,
            _ => new CliEnvironment(new AppPaths(_dir), new FakeNetwork(Adapter()), backend ?? new FakeBackend(), catalog, _exitEvent));
        var code = await runner.RunAsync(args);
        return (code, stdout.ToString(), stderr.ToString());
    }

    // ---------------- Parsing ----------------

    [Fact]
    public void Options_are_parsed_and_validated()
    {
        var o = CliOptions.Parse(new[] { "scan", "192.168.1.0/24,192.168.2.5", "-i", "WLAN", "--ports", "22,80,8000-8002", "--json", "--fail-on", "MEDIUM" });
        Assert.Null(o.Error);
        Assert.Equal(new[] { "192.168.1.0/24", "192.168.2.5" }, o.Targets);
        Assert.Equal("WLAN", o.Interface);
        Assert.Equal("custom", o.Profile);
        Assert.Equal(new[] { 22, 80, 8000, 8001, 8002 }, o.Ports);
        Assert.Equal("json", o.Format);
        Assert.Equal("medium", o.FailOn);

        Assert.Equal("help", CliOptions.Parse(Array.Empty<string>()).Command);
        Assert.Equal("version", CliOptions.Parse(new[] { "--version" }).Command);
        Assert.NotNull(CliOptions.Parse(new[] { "scna" }).Error);
        Assert.NotNull(CliOptions.Parse(new[] { "scan", "--ports", "0" }).Error);
        Assert.NotNull(CliOptions.Parse(new[] { "scan", "--ports", "1-2000" }).Error);
        Assert.NotNull(CliOptions.Parse(new[] { "scan", "--profile", "standard", "--ports", "22" }).Error);
        Assert.NotNull(CliOptions.Parse(new[] { "scan", "--format", "xml" }).Error);
        Assert.NotNull(CliOptions.Parse(new[] { "scan", "--interface" }).Error);
        Assert.NotNull(CliOptions.Parse(new[] { "show" }).Error);
        Assert.NotNull(CliOptions.Parse(new[] { "interfaces", "extra" }).Error);
    }

    [Fact]
    public async Task Usage_errors_exit_with_code_2()
    {
        var (code, _, err) = await Run(args: new[] { "scan", "--bogus" });
        Assert.Equal(CliRunner.ExitUsage, code);
        Assert.Contains("Unknown option", err);

        // A target outside the adapter's network is refused before anything is sent.
        (code, _, err) = await Run(args: new[] { "scan", "8.8.8.8", "--interface", "192.168.77.10", "--no-progress" });
        Assert.Equal(CliRunner.ExitUsage, code);
        Assert.Contains("not a private address", err, StringComparison.OrdinalIgnoreCase);

        (code, _, err) = await Run(args: new[] { "scan", "10.9.9.9", "--interface", "192.168.77.10" });
        Assert.Equal(CliRunner.ExitUsage, code);
        Assert.Contains("outside the adapter's network 192.168.77.0/24", err);
    }

    // ---------------- Scan and output formats ----------------

    [Fact]
    public async Task Scan_prints_devices_findings_and_is_saved_to_history()
    {
        var (code, output, err) = await Run(args: new[] { "scan", "192.168.77.20-21", "--ports", "445,3389" });
        Assert.Equal(CliRunner.ExitOk, code);
        Assert.Contains("Scanning 192.168.77.20-21 from Test", err);
        Assert.Contains("completed", output);
        Assert.Contains("192.168.77.20", output);
        Assert.Contains("445", output);
        Assert.Contains("MEDIUM", output);                 // SMB rule
        Assert.Contains("File sharing (SMB)", output);
        Assert.DoesNotContain("192.168.77.21", output);    // silent address is not a device

        var (hcode, history, _) = await Run(args: new[] { "history" });
        Assert.Equal(CliRunner.ExitOk, hcode);
        Assert.Contains("completed", history);
        Assert.Contains("192.168.77.0/24", history);
    }

    [Fact]
    public async Task Json_and_csv_output_are_machine_readable()
    {
        var (code, json, _) = await Run(args: new[] { "scan", "192.168.77.20", "--ports", "445,3389", "--format", "json" });
        Assert.Equal(CliRunner.ExitOk, code);
        var doc = JsonDocument.Parse(json).RootElement;
        Assert.Equal("completed", doc.GetProperty("scan").GetProperty("state").GetString());
        var host = Assert.Single(doc.GetProperty("hosts").EnumerateArray());
        Assert.Equal("192.168.77.20", host.GetProperty("ip").GetString());
        var scanId = doc.GetProperty("scan").GetProperty("id").GetString()!;

        // "show" accepts the short id that "history" prints.
        var (scode, csv, _) = await Run(args: new[] { "show", scanId[..8], "--csv" });
        Assert.Equal(CliRunner.ExitOk, scode);
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.StartsWith("scan_id,scan_state,ip,", lines[0]);
        var row = Assert.Single(lines.Skip(1));
        Assert.Contains(",192.168.77.20,", row);
        Assert.Contains(",tcp,445,open,", row);
        Assert.EndsWith(",medium,R04", row);
    }

    [Fact]
    public void Csv_cells_are_quoted_and_formulas_neutralised()
    {
        Assert.Equal("\"'=HYPERLINK(\"\"x\"\")\"", Csv.Cell("=HYPERLINK(\"x\")"));
        Assert.Equal("\"a,b\"", Csv.Cell("a,b"));
        Assert.Equal("'@SUM(A1)", Csv.Cell("@SUM(A1)"));
        Assert.Equal("", Csv.Cell(null));
    }

    [Fact]
    public async Task Fail_on_sets_exit_code_3_for_findings_at_that_level()
    {
        var (medium, _, _) = await Run(args: new[] { "scan", "192.168.77.20", "--ports", "445", "--fail-on", "medium", "--format", "json" });
        Assert.Equal(CliRunner.ExitFindings, medium);
        var (high, _, _) = await Run(args: new[] { "scan", "192.168.77.20", "--ports", "445", "--fail-on", "high", "--format", "json" });
        Assert.Equal(CliRunner.ExitOk, high);
    }

    [Fact]
    public async Task Cancel_line_on_stdin_stops_the_scan_and_keeps_results()
    {
        var input = new CancelInput();
        var backend = new FakeBackend
        {
            // 3389 hangs until the scan is cancelled; once it is being probed, the "cancel" line is sent.
            BeforeProbe = async (port, ct) =>
            {
                if (port != 3389) return;
                await Task.Delay(300, ct);   // let 445 (probed in parallel) finish first
                input.Send.TrySetResult();
                await Task.Delay(Timeout.Infinite, ct);
            },
        };
        var (code, output, err) = await Run(backend, input, "scan", "192.168.77.20", "--ports", "445,3389");
        Assert.Equal(CliRunner.ExitIncomplete, code);
        Assert.Contains("Cancelling", err);
        Assert.Contains("cancelled", output);
        Assert.Contains("445", output);   // the port measured before the cancel is kept
    }

    [Fact]
    public async Task Progress_is_written_to_stderr_only_when_requested()
    {
        var input = new CancelInput();
        var slow = new FakeBackend { BeforeProbe = (_, ct) => Task.Delay(700, ct) };
        var (_, output, err) = await Run(slow, input, "scan", "192.168.77.20", "--ports", "445", "--progress");
        Assert.Contains("\r[", err);
        Assert.DoesNotContain("\r[", output);
    }

    // ---------------- Setup asks LANORA to exit (ExitRequest) ----------------

    [Fact]
    public async Task No_command_runs_while_setup_has_asked_lanora_to_exit()
    {
        using var request = ExitRequest.Open(_exitEvent);
        request.Set();
        var (code, output, err) = await Run(args: new[] { "scan", "192.168.77.20", "--ports", "445" });
        Assert.Equal(CliRunner.ExitError, code);
        Assert.Contains("being installed or removed", err);
        Assert.Equal("", output);
    }

    [Fact]
    public async Task Exit_request_during_a_scan_cancels_it_and_keeps_results()
    {
        using var request = ExitRequest.Open(_exitEvent);
        var backend = new FakeBackend
        {
            // 3389 hangs; once it is being probed (445 is done), setup "asks LANORA to exit".
            BeforeProbe = async (port, ct) =>
            {
                if (port != 3389) return;
                await Task.Delay(300, ct);
                request.Set();
                await Task.Delay(Timeout.Infinite, ct);
            },
        };
        var (code, output, err) = await Run(backend, null, "scan", "192.168.77.20", "--ports", "445,3389");
        Assert.Equal(CliRunner.ExitIncomplete, code);
        Assert.Contains("being installed or removed: cancelling", err);
        Assert.Contains("cancelled", output);
        Assert.Contains("445", output);
    }

    [Fact]
    public void Exit_request_name_matches_the_installer_script()
    {
        var root = AppContext.BaseDirectory;
        while (root is not null && !File.Exists(Path.Combine(root, "Lanora.slnx"))) root = Path.GetDirectoryName(root);
        var iss = File.ReadAllText(Path.Combine(root!, "packaging", "Lanora.iss"));
        Assert.Contains($"ExitEventName = '{ExitRequest.DefaultName}';", iss);
        // Setup must close LANORA before installing and before uninstalling.
        Assert.Contains("function PrepareToInstall", iss);
        Assert.Contains("function InitializeUninstall", iss);
    }

    // ---------------- Adapter selection ----------------

    [Fact]
    public void Adapter_is_chosen_by_target_name_or_default_route()
    {
        var a = Fixtures.Adapter("192.168.77.10", 24, "192.168.77.1") with { Name = "Ethernet" };
        var b = Fixtures.Adapter("10.0.0.5", 24, "10.0.0.1") with { Name = "WLAN", Id = "test/10.0.0.5" };

        Assert.Equal("WLAN", CliRunner.SelectAdapter(new[] { a, b }, CliOptions.Parse(new[] { "scan", "10.0.0.0/24" })).Adapter!.Name);
        Assert.Equal("Ethernet", CliRunner.SelectAdapter(new[] { a, b }, CliOptions.Parse(new[] { "scan", "-i", "ethernet" })).Adapter!.Name);
        var (none, problem) = CliRunner.SelectAdapter(new[] { a, b }, CliOptions.Parse(new[] { "scan" }));
        Assert.Null(none);
        Assert.Contains("--interface", problem);
        Assert.Equal("WLAN", CliRunner.SelectAdapter(new[] { a, b with { IsDefaultRoute = true } }, CliOptions.Parse(new[] { "scan" })).Adapter!.Name);
    }

    // ---------------- Shared database (window app + command line) ----------------

    [Fact]
    public async Task Startup_interrupts_only_scans_whose_process_is_gone()
    {
        var (_, json, _) = await Run(args: new[] { "scan", "192.168.77.20", "--ports", "445", "--json" });
        var done = JsonDocument.Parse(json).RootElement.GetProperty("scan").GetProperty("id").GetString()!;
        var (_, json2, _) = await Run(args: new[] { "scan", "192.168.77.20", "--ports", "445", "--json" });
        var other = JsonDocument.Parse(json2).RootElement.GetProperty("scan").GetProperty("id").GetString()!;

        var db = new Database(new AppPaths(_dir));
        await db.WriteAsync((c, tx) =>
        {
            // One scan "running" in this (live) process, one owned by a process that no longer exists.
            Db.Exec(c, tx, "UPDATE scan SET state='running', owner=$o WHERE id=$id", ("$o", ProcessOwner.Current), ("$id", done));
            Db.Exec(c, tx, "UPDATE scan SET state='running', owner='999999:1' WHERE id=$id", ("$id", other));
        });
        db.Initialize();   // what the window app or the next command does at startup
        var store = new ScanStore(db);
        Assert.Equal(ScanStates.Running, store.GetSummary(done)!.State);
        Assert.Equal(ScanStates.Interrupted, store.GetSummary(other)!.State);
        db.Dispose();

        Assert.True(ProcessOwner.IsAlive(ProcessOwner.Current));
        Assert.False(ProcessOwner.IsAlive(null));
        Assert.False(ProcessOwner.IsAlive("not-an-owner"));
    }

    // ---------------- Packaging ----------------

    [Fact]
    public void Launcher_version_matches_the_application_version()
    {
        var root = AppContext.BaseDirectory;
        while (root is not null && !File.Exists(Path.Combine(root, "Lanora.slnx"))) root = Path.GetDirectoryName(root);
        Assert.NotNull(root);
        static string Version(string path) => System.Xml.Linq.XDocument.Load(path).Descendants("Version").First().Value;
        Assert.Equal(Version(Path.Combine(root!, "src", "Lanora", "Lanora.csproj")),
            Version(Path.Combine(root!, "src", "Lanora.Launcher", "Lanora.Launcher.csproj")));
    }
}
