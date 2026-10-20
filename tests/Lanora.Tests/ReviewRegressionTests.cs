using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Lanora.Data;
using Lanora.Infrastructure;
using Lanora.Net;
using Lanora.Reports;
using Lanora.Risk;
using Lanora.Scanning;
using Lanora.Scanning.Advanced;
using Lanora.Scanning.Native;

namespace Lanora.Tests;

/// <summary>Regression tests for the findings (F01–F15) of the code audit report.</summary>
public class ReviewRegressionTests
{
    // ---------------- Shared helpers ----------------

    /// <summary>Scan backend that never touches the network; its behavior is set by the test.</summary>
    private sealed class FakeBackend : IScanBackend
    {
        public string Name => "fake";
        public string Version => "fake-1";
        public int? Ttl { get; init; } = 128;
        public Func<uint, int, CancellationToken, Task<ProbeResult>> Tcp { get; init; } =
            (_, port, _) => Task.FromResult(port == 1 ? new ProbeResult(PortState.Open, "syn_ack", 1) : new ProbeResult(PortState.Closed, "conn_refused", 1));

        public Task<ProbeResult> ProbeTcpAsync(uint ip, int port, int timeoutMs, CancellationToken ct) => Tcp(ip, port, ct);
        public Func<uint, CancellationToken, Task<(bool, int?)>>? Ping { get; init; }
        public Task<(bool Reply, int? Ttl)> PingAsync(uint ip, int timeoutMs, CancellationToken ct) => Ping?.Invoke(ip, ct) ?? Task.FromResult((true, Ttl));
    }

    private sealed class Rig : IDisposable
    {
        private readonly string _dir = Path.Combine(Path.GetTempPath(), "lanora-review-" + Guid.NewGuid().ToString("N"));
        public Database Db { get; }
        public ScanStore Store { get; }
        public ScanOrchestrator Orch { get; }

        public Rig(IScanBackend backend, int timeBudgetMinutes = 15)
        {
            Db = new Database(new AppPaths(_dir));
            Db.Initialize();
            Store = new ScanStore(Db);
            var defaults = Res.ReadJson<ProfileFile>("res/profiles.json");
            var catalog = new PortCatalog(new ProfileFile
            {
                Version = defaults.Version,
                Profiles = defaults.Profiles,
                Rate = new RateSettings { TimeBudgetMinutes = timeBudgetMinutes, NewConnectionsPerSecond = 1000 },
            });
            Orch = new ScanOrchestrator(new NetworkInfoService(), catalog, new RiskEngine(new Ruleset()), Store, new BadgeService(Db),
                new OuiDatabase(), backend, new ServiceProber(), Db);
        }

        public async Task<string> RunAsync(AdvancedScanRequest req, Func<string, Task>? whileRunning = null)
        {
            var (id, _) = await Orch.StartAdvancedAsync(req, null);
            if (whileRunning is not null) await whileRunning(id);
            await Orch.GetJob(id)!.Runner!.WaitAsync(TimeSpan.FromSeconds(30));
            return id;
        }

        public void Dispose()
        {
            Db.Dispose();
            try { Directory.Delete(_dir, true); } catch { }
        }
    }

    /// <summary>Advanced scan request that produces no real network traffic (ICMP/DNS/UDP/service probes off).</summary>
    private static AdvancedScanRequest OfflineRequest(params int[] ports) => new()
    {
        Targets = { "192.0.2.10" },
        Authorized = true,
        PortScope = "custom",
        TcpPorts = ports.ToList(),
        ReverseDns = false,
        ServiceVersion = false,
        ServiceChecks = false,
        Traceroute = false,
        OsDetection = true,
    };

    private static AdapterInfo Adapter(bool selectable = true)
    {
        var net = Cidr.FromAddress(Ipv4.Parse("192.168.1.10"), 24);
        return new AdapterInfo
        {
            Id = "test/192.168.1.10", AdapterGuid = "{t}", Name = "T", Description = "T", Kind = "ethernet",
            Ip = "192.168.1.10", PrefixLength = 24, NetworkCidr = net.ToString(), Gateway = "192.168.1.1",
            Selectable = selectable, IsPrivate = true, Ranges = new[] { net.ToString() }, SuggestedRange = net.ToString(),
            AddressCount = 256,
        };
    }

    private static IReadOnlyList<string> NoDns(string _) => Array.Empty<string>();

    // ---------------- F01 oturum denetimi ----------------

    private static async Task<(LanoraHost Host, HttpClient Http, string Dir)> StartHostAsync()
    {
        var dir = Path.Combine(Path.GetTempPath(), "lanora-api-" + Guid.NewGuid().ToString("N"));
        var host = await LanoraHost.StartAsync(new AppPaths(dir));
        var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{host.Port}") };
        return (host, http, dir);
    }

    private static async Task StopHostAsync(LanoraHost host, HttpClient http, string dir)
    {
        http.Dispose();
        await host.DisposeAsync();
        try { Directory.Delete(dir, true); } catch { }
    }

    [Theory]
    [InlineData("/API/v1/settings")]
    [InlineData("/Api/v1/settings")]
    [InlineData("/aPi/v1/settings")]
    [InlineData("/api/V1/SETTINGS")]
    [InlineData("/API/v1/scans")]
    [InlineData("/API/v1/dashboard")]
    [InlineData("/API/v1/scans/x/events")]
    public async Task Api_case_variants_require_authentication(string path)
    {
        var (host, http, dir) = await StartHostAsync();
        try
        {
            var get = await http.GetAsync(path);
            Assert.Equal(HttpStatusCode.Unauthorized, get.StatusCode);
            var head = await http.SendAsync(new HttpRequestMessage(HttpMethod.Head, path));
            Assert.Equal(HttpStatusCode.Unauthorized, head.StatusCode);
        }
        finally { await StopHostAsync(host, http, dir); }
    }

    [Fact]
    public async Task Api_case_variant_cannot_download_private_report_without_token()
    {
        var (host, http, dir) = await StartHostAsync();
        try
        {
            var r = await http.GetAsync("/API/v1/scans/any-id/report?format=xlsx&lang=tr");
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
            Assert.NotEqual("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", r.Content.Headers.ContentType?.MediaType);
        }
        finally { await StopHostAsync(host, http, dir); }
    }

    // ---------------- F12 wrong JSON type ----------------

    [Theory]
    [InlineData("{\"lang\":123}")]
    [InlineData("{\"theme\":true}")]
    [InlineData("{\"retention\":[1]}")]
    [InlineData("{\"default_profile\":{}}")]
    public async Task Api_wrong_json_field_type_returns_client_error(string body)
    {
        var (host, http, dir) = await StartHostAsync();
        try
        {
            var secret = host.Sessions.CreateBootstrapSecret();
            var boot = await http.PostAsync("/api/v1/session/bootstrap", new StringContent($"{{\"secret\":\"{secret}\"}}", Encoding.UTF8, "application/json"));
            boot.EnsureSuccessStatusCode();
            var token = JsonDocument.Parse(await boot.Content.ReadAsStringAsync()).RootElement.GetProperty("token").GetString();
            var req = new HttpRequestMessage(HttpMethod.Patch, "/api/v1/settings") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var r = await http.SendAsync(req);
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
            Assert.Contains("SETTING_INVALID", await r.Content.ReadAsStringAsync());
        }
        finally { await StopHostAsync(host, http, dir); }
    }

    // ---------------- F02 keeping results on cancel ----------------

    [Fact]
    public async Task Advanced_cancel_keeps_completed_observations()
    {
        var waiting = 0;
        var backend = new FakeBackend
        {
            Tcp = async (_, port, ct) =>
            {
                if (port == 1) return new ProbeResult(PortState.Open, "syn_ack", 1);
                Interlocked.Increment(ref waiting);
                await Task.Delay(Timeout.Infinite, ct);
                throw new OperationCanceledException(ct);
            },
        };
        using var rig = new Rig(backend);
        var id = await rig.RunAsync(OfflineRequest(1, 2, 3), async scanId =>
        {
            var until = DateTime.UtcNow.AddSeconds(10);
            while (Volatile.Read(ref waiting) < 2 && DateTime.UtcNow < until) await Task.Delay(20);
            await Task.Delay(200);
            Assert.True(rig.Orch.Cancel(scanId));
        });

        Assert.Equal(ScanStates.Cancelled, rig.Store.GetSummary(id)!.State);
        var host = Assert.Single(rig.Store.GetHosts(id, allObservations: true));
        Assert.Contains(host.Open, o => o.Port == 1 && o.State == PortState.Open);
        // Unmeasured ports are not lost; they are marked "not tested".
        Assert.Contains(host.Open, o => o.Port == 2 && o.State == PortState.NotTested && o.ReasonCode == "cancelled");
        Assert.Contains(host.Open, o => o.Port == 3 && o.State == PortState.NotTested);
    }

    [Fact]
    public async Task Advanced_cancel_during_discovery_keeps_found_devices()
    {
        var slowStarted = 0;
        var backend = new FakeBackend
        {
            Ping = async (ip, ct) =>
            {
                if (ip == Ipv4.Parse("192.0.2.10")) return (true, 64);
                Interlocked.Increment(ref slowStarted);
                await Task.Delay(Timeout.Infinite, ct);
                return (false, null);
            },
        };
        using var rig = new Rig(backend);
        var req = OfflineRequest(1, 2);
        req.Targets = new() { "192.0.2.10", "192.0.2.11" };
        var id = await rig.RunAsync(req, async scanId =>
        {
            var until = DateTime.UtcNow.AddSeconds(10);
            while (Volatile.Read(ref slowStarted) < 1 && DateTime.UtcNow < until) await Task.Delay(20);
            await Task.Delay(200);
            rig.Orch.Cancel(scanId);
        });

        Assert.Equal(ScanStates.Cancelled, rig.Store.GetSummary(id)!.State);
        var host = Assert.Single(rig.Store.GetHosts(id, allObservations: true));
        Assert.Equal("192.0.2.10", host.Ip);
        Assert.All(host.Open, o => Assert.Equal(PortState.NotTested, o.State));
        Assert.Equal(2, host.Open.Count);
    }

    // ---------------- F03 comparison and second report ----------------

    [Fact]
    public async Task Advanced_scan_comparison_and_second_report_do_not_throw()
    {
        using var rig = new Rig(new FakeBackend());
        var first = await rig.RunAsync(OfflineRequest(1, 2));
        var second = await rig.RunAsync(OfflineRequest(1, 2));
        Assert.Equal(ScanStates.Completed, rig.Store.GetSummary(second)!.State);

        var cmp = rig.Store.Compare(second, first);
        Assert.NotNull(cmp);
        var json = JsonSerializer.SerializeToElement(cmp, Json.Options);
        Assert.True(json.GetProperty("compatible").GetBoolean());

        var builder = new ReportBuilder(rig.Store, new Ruleset(), rig.Orch);
        foreach (var lang in new[] { "tr", "en" })
        {
            var data = builder.Build(second, lang)!;
            Assert.True(PdfReport.Render(data).Length > 1000);
            Assert.True(XlsxReport.Render(data).Length > 1000);
        }
    }

    // ---------------- F04 time budget ----------------

    [Fact]
    public async Task Advanced_scan_obeys_the_configured_time_budget()
    {
        var backend = new FakeBackend { Tcp = async (_, _, ct) => { await Task.Delay(Timeout.Infinite, ct); throw new OperationCanceledException(ct); } };
        using var rig = new Rig(backend, timeBudgetMinutes: 0);
        var id = await rig.RunAsync(OfflineRequest(1, 2, 3));
        var s = rig.Store.GetSummary(id)!;
        Assert.Equal(ScanStates.Partial, s.State);
        Assert.Equal("TIME_BUDGET_EXCEEDED", s.ReasonCode);
    }

    [Fact]
    public void Advanced_plan_rejects_unbounded_probe_product()
    {
        var req = new AdvancedScanRequest { Targets = { "192.168.1.0/24" }, PortScope = "all" };
        var ex = Assert.Throws<ApiException>(() => AdvancedScanValidator.Build(req, Adapter(), NoDns));
        Assert.Equal("ATTEMPT_BUDGET_EXCEEDED", ex.Code);
    }

    // ---------------- F05 / F06 scope ----------------

    [Fact]
    public void Advanced_disabled_adapter_does_not_authorize_external_targets()
    {
        var req = new AdvancedScanRequest { Targets = { "203.0.113.9" }, Authorized = false };
        var ex = Assert.Throws<ApiException>(() => AdvancedScanValidator.Build(req, Adapter(selectable: false), NoDns));
        Assert.Equal("AUTHORIZATION_REQUIRED", ex.Code);

        var ok = AdvancedScanValidator.Build(new AdvancedScanRequest { Targets = { "203.0.113.9" }, Authorized = true }, Adapter(selectable: false), NoDns);
        Assert.True(ok.AnyExternal);
        Assert.All(ok.Targets, t => Assert.False(t.IsLocal));
    }

    [Fact]
    public void Advanced_subnet_excludes_network_and_broadcast()
    {
        var plan = AdvancedScanValidator.Build(new AdvancedScanRequest { Targets = { "192.168.1.0/24" } }, Adapter(), NoDns);
        Assert.Equal(254, plan.IpTargets.Count);
        Assert.DoesNotContain(Ipv4.Parse("192.168.1.0"), plan.IpTargets);
        Assert.DoesNotContain(Ipv4.Parse("192.168.1.255"), plan.IpTargets);
    }

    // ---------------- F07 / F08 port scope ----------------

    [Fact]
    public void Advanced_udp_only_all_scope_does_not_schedule_tcp()
    {
        var plan = AdvancedScanValidator.Build(new AdvancedScanRequest { Targets = { "192.168.1.5" }, Technique = "udp", PortScope = "all" }, Adapter(), NoDns);
        Assert.Empty(plan.TcpPorts);
        Assert.NotEmpty(plan.UdpPorts);

        var custom = AdvancedScanValidator.Build(new AdvancedScanRequest { Targets = { "192.168.1.5" }, Technique = "udp", PortScope = "custom", TcpPorts = new() { 80 }, UdpPorts = new() { 53 } }, Adapter(), NoDns);
        Assert.Empty(custom.TcpPorts);
        Assert.Equal(new[] { 53 }, custom.UdpPorts);
    }

    [Theory]
    [InlineData(20)]
    [InlineData(1000)]
    [InlineData(5000)]
    public void Advanced_top_1000_does_not_silently_schedule_fewer_ports(int n)
    {
        var plan = AdvancedScanValidator.Build(new AdvancedScanRequest { Targets = { "192.168.1.5" }, PortScope = "top", TopPorts = n }, Adapter(), NoDns);
        Assert.Equal(n, plan.TcpPorts.Count);
        Assert.Equal(n, plan.TcpPorts.Distinct().Count());
        Assert.Contains(22, plan.TcpPorts); // priority ports come first
    }

    [Fact]
    public void Advanced_top_ports_out_of_range_is_rejected()
    {
        var ex = Assert.Throws<ApiException>(() => AdvancedScanValidator.Build(new AdvancedScanRequest { Targets = { "192.168.1.5" }, PortScope = "top", TopPorts = 70000 }, Adapter(), NoDns));
        Assert.Equal("PORT_LIMIT", ex.Code);
    }

    // ---------------- F09 OS option ----------------

    [Fact]
    public async Task Advanced_os_detection_false_does_not_publish_os_guess()
    {
        using var rig = new Rig(new FakeBackend { Ttl = 128 });
        var req = OfflineRequest(1);
        req.OsDetection = false;
        var id = await rig.RunAsync(req);
        var host = Assert.Single(rig.Store.GetHosts(id));
        Assert.Null(host.OsCandidate);
        Assert.Null(host.OsSource);

        var withOs = await rig.RunAsync(OfflineRequest(1));
        Assert.NotNull(Assert.Single(rig.Store.GetHosts(withOs)).OsCandidate);
    }

    // ---------------- F11 counters ----------------

    [Fact]
    public async Task Advanced_scan_summary_reports_the_actual_port_count()
    {
        using var rig = new Rig(new FakeBackend());
        var id = await rig.RunAsync(OfflineRequest(1, 2, 3));
        var s = rig.Store.GetSummary(id)!;
        Assert.Equal(3, s.PortCount);
        Assert.True(s.Attempts >= 3, $"attempts={s.Attempts}");
    }

    // ---------------- F10 FTP anonymous check ----------------

    [Fact]
    public async Task Ftp_anonymous_check_handles_normal_long_greeting()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII);
            var w = new StreamWriter(stream, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };
            await w.WriteLineAsync("220-" + new string('x', 300));
            await w.WriteLineAsync("220-Bu sunucu uzun bir karsilama metni gonderir.");
            await w.WriteLineAsync("220 Service ready");
            var user = await reader.ReadLineAsync();
            await w.WriteLineAsync(user == "USER anonymous" ? "331 Please specify the password." : "500 Unexpected");
            await reader.ReadLineAsync();
            await w.WriteLineAsync("230 Login successful.");
            await reader.ReadLineAsync(); // QUIT
        });

        var scripts = new List<ScriptEvidence>();
        await NativeScripts.FtpAnon(Ipv4.Parse("127.0.0.1"), port, scripts, CancellationToken.None);
        await server.WaitAsync(TimeSpan.FromSeconds(10));
        var s = Assert.Single(scripts);
        Assert.Contains("accepted", s.Output);
    }

    // ---------------- F13 hostname starting with a digit ----------------

    [Fact]
    public void Advanced_digit_prefixed_hostname_uses_dns_resolver()
    {
        var called = false;
        var plan = AdvancedScanValidator.Build(new AdvancedScanRequest { Targets = { "3d-printer.local" }, Authorized = true }, Adapter(),
            name => { called = name == "3d-printer.local"; return new[] { "192.0.2.50" }; });
        Assert.True(called);
        var t = Assert.Single(plan.Targets);
        Assert.True(t.IsHostname);
        Assert.Equal("192.0.2.50", t.Resolved);
    }

    // ---------------- F14 SNMP OID ----------------

    [Fact]
    public void Snmp_probe_requests_a_scalar_oid_with_instance_identifier()
    {
        var probe = UdpProber.BuildProbe(161);
        var oid = new byte[] { 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00 }; // 1.3.6.1.2.1.1.1.0
        Assert.True(probe.AsSpan().IndexOf(oid) >= 0, Convert.ToHexString(probe));
        // The outer SEQUENCE length must match the rest of the message.
        Assert.Equal(0x30, probe[0]);
        Assert.Equal(probe.Length - 2, probe[1]);
        // The GetRequest PDU (0xA0) and community "public" must be present.
        Assert.Contains((byte)0xA0, probe);
        Assert.True(probe.AsSpan().IndexOf("public"u8) > 0);
    }
}
