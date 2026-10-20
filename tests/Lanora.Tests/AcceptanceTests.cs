using ClosedXML.Excel;
using Lanora.Data;
using Lanora.Infrastructure;
using Lanora.Net;
using Lanora.Reports;
using Lanora.Risk;
using Lanora.Scanning;
using Lanora.Security;

namespace Lanora.Tests;

internal static class Fixtures
{
    public static AdapterInfo Adapter(string ip = "192.168.1.10", int prefix = 24, string? gw = "192.168.1.1")
    {
        var value = Ipv4.Parse(ip);
        var net = Cidr.FromAddress(value, prefix);
        var (ranges, suggested, required) = NetworkInfoService.BuildRanges(net, value);
        return new AdapterInfo
        {
            Id = "test/" + ip, AdapterGuid = "{test}", Name = "Test", Description = "Test adapter", Kind = "ethernet",
            Ip = ip, PrefixLength = prefix, NetworkCidr = net.ToString(), Gateway = gw, Mac = "AA:BB:CC:00:00:01",
            Selectable = true, IsPrivate = true, Ranges = ranges, SuggestedRange = suggested, RangeSelectionRequired = required,
            AddressCount = net.AddressCount,
        };
    }

    /// <summary>open: port → (telnet, ftp) evidence; closed/silent: closed and unresponsive ports.</summary>
    public static HostResult Host(string ip, int[] open, int closed = 0, int silent = 0, bool telnet = false, bool ftp = false, string? mac = null)
    {
        var h = new HostResult { Ip = Ipv4.Parse(ip), Mac = mac };
        h.DiscoveryEvidence.Add("icmp");
        foreach (var p in open)
            h.Ports[p] = new PortObservationResult
            {
                Protocol = "tcp", Port = p, State = PortState.Open, Attempts = 1,
                Service = new ServiceEvidence { TelnetVerified = telnet && p == 23, FtpVerified = ftp && p == 21 },
            };
        var next = 40000;
        for (var i = 0; i < closed; i++) { var p = next++; h.Ports[p] = new PortObservationResult { Protocol = "tcp", Port = p, State = PortState.Closed, Attempts = 1 }; }
        for (var i = 0; i < silent; i++) { var p = next++; h.Ports[p] = new PortObservationResult { Protocol = "tcp", Port = p, State = PortState.NoResponse, Attempts = 2 }; }
        return h;
    }
}

public class NetworkTests
{
    [Fact] // FR01: 192.168.10.25/23 → 192.168.10.0/23, no /24 assumption
    public void Cidr_uses_real_prefix()
    {
        var c = Cidr.FromAddress(Ipv4.Parse("192.168.10.25"), 23);
        Assert.Equal("192.168.10.0/23", c.ToString());
        Assert.Equal(512, c.AddressCount);
        var a = Fixtures.Adapter("192.168.10.25", 23);
        Assert.Equal("192.168.10.0/23", a.NetworkCidr);
        Assert.True(a.RangeSelectionRequired);
        Assert.Equal("192.168.10.0/24", a.SuggestedRange);
    }

    [Theory] // FR02: out-of-subnet, public IP, hostname and 257 addresses are rejected
    [InlineData("192.168.2.5", 403, "TARGET_OUT_OF_SCOPE")]
    [InlineData("8.8.8.8", 403, "TARGET_NOT_PRIVATE")]
    [InlineData("router.local", 400, "TARGET_INVALID")]
    [InlineData("http://example.com", 400, "TARGET_INVALID")]
    [InlineData("192.168.1.0/23", 400, "TARGET_LIMIT")]
    [InlineData("0x7f.1", 400, "TARGET_INVALID")]
    public void Invalid_targets_are_rejected(string target, int status, string code)
    {
        var ex = Assert.Throws<TargetValidationException>(() => TargetValidator.Validate(Fixtures.Adapter(), new[] { target }));
        Assert.Equal(status, ex.Status);
        Assert.Equal(code, ex.Code);
    }

    [Fact]
    public void Request_with_257_addresses_is_rejected()
    {
        var a = Fixtures.Adapter("10.0.5.20", 16, "10.0.0.1");
        var ex = Assert.Throws<TargetValidationException>(() => TargetValidator.Validate(a, new[] { "10.0.5.0/24", "10.0.6.1" }));
        Assert.Equal("TARGET_LIMIT", ex.Code);
    }

    [Fact] // Network and broadcast addresses are removed, duplicates are deduplicated
    public void Network_and_broadcast_are_excluded_and_targets_deduplicated()
    {
        var plan = TargetValidator.Validate(Fixtures.Adapter(), new[] { "192.168.1.0/24", "192.168.1.5", "192.168.1.5" });
        Assert.Equal(254, plan.Targets.Count);
        Assert.Contains("192.168.1.0", plan.Excluded);
        Assert.Contains("192.168.1.255", plan.Excluded);
        Assert.Equal(Ipv4.Parse("192.168.1.10"), plan.LocalIp);
    }

    [Fact]
    public void Ranges_are_supported()
    {
        var plan = TargetValidator.Validate(Fixtures.Adapter(), new[] { "192.168.1.20-25" });
        Assert.Equal(6, plan.Targets.Count);
    }

    [Fact]
    public void Locally_administered_mac_has_no_vendor()
    {
        var oui = new OuiDatabase();
        Assert.True(MacAddress.IsLocallyAdministered("02:8C:36:79:5A:11"));
        Assert.Null(oui.Lookup("02:8C:36:79:5A:11"));
        Assert.Null(oui.Lookup(null));
    }
}

public class ProfileTests
{
    [Fact]
    public void Quick_and_standard_profiles_match_spec()
    {
        var c = new PortCatalog();
        var quick = c.Get("quick")!;
        var standard = c.Get("standard")!;
        Assert.Equal(32, quick.Ports!.Length);
        Assert.Equal(800, quick.TimeoutMs);
        Assert.Equal(128, standard.Ports!.Length);
        Assert.Equal(1000, standard.TimeoutMs);
        Assert.Subset(standard.Ports!.ToHashSet(), quick.Ports!.ToHashSet());
        Assert.Equal(64, c.Rate.GlobalConcurrency);
        Assert.Equal(4, c.Rate.PerHostConcurrency);
        Assert.Equal(100, c.Rate.NewConnectionsPerSecond);
        Assert.False(c.Get("advanced")!.Available);
        Assert.Equal(new[] { 53, 123, 137, 161, 1900, 3702, 5353, 5355 }, c.Get("advanced")!.UdpPorts);
    }
}

public class ScoringTests
{
    private readonly RiskEngine _risk = new(new Ruleset());

    private (HostScore Score, IReadOnlyList<FindingResult> Findings) Eval(HostResult h)
    {
        var f = _risk.Evaluate(h);
        return (RiskEngine.ScoreHost(h, f), f);
    }

    [Fact] // TC08: RDP open → 85
    public void Rdp_only_scores_85()
    {
        var (s, f) = Eval(Fixtures.Host("192.168.1.20", new[] { 3389 }, closed: 31));
        Assert.Equal(85, s.Score);
        Assert.Contains(f, x => x.RuleId == "R03" && x.Severity == "high");
    }

    [Fact] // TC08: verified Telnet + RDP → 60; network indicator 60
    public void Verified_telnet_and_rdp_score_60_and_network_is_minimum()
    {
        var a = Eval(Fixtures.Host("192.168.1.20", new[] { 3389 }, closed: 31));
        var b = Eval(Fixtures.Host("192.168.1.21", new[] { 23, 3389 }, closed: 30, telnet: true));
        Assert.Equal(60, b.Score.Score);
        var net = RiskEngine.ScoreNetwork(new[] { a.Score, b.Score }, provisional: false);
        Assert.Equal(60, net.Score);
        Assert.Equal("ok", net.State);
    }

    [Fact] // The same finding is not deducted twice (a repeated banner does not change the score)
    public void Same_port_is_penalised_once()
    {
        var h = Fixtures.Host("192.168.1.20", new[] { 23 }, closed: 31, telnet: true);
        var findings = _risk.Evaluate(h).ToList();
        findings.Add(findings.First(f => f.RuleId == "R01"));
        Assert.Equal(75, RiskEngine.ScoreHost(h, findings).Score);
    }

    [Fact] // R05: 21/23 open but service not verified → 10, medium
    public void Unverified_telnet_port_uses_r05()
    {
        var (s, f) = Eval(Fixtures.Host("192.168.1.20", new[] { 23 }, closed: 31));
        Assert.Contains(f, x => x.RuleId == "R05" && x.Severity == "medium" && x.Penalty == 10);
        Assert.Equal(90, s.Score);
    }

    [Fact] // R06: HTTPS open is informational only, no penalty
    public void Https_is_informational()
    {
        var (s, f) = Eval(Fixtures.Host("192.168.1.20", new[] { 443, 80 }, closed: 30));
        Assert.All(f.Where(x => x.Port > 0), x => Assert.Equal("R06", x.RuleId));
        Assert.Equal(100, s.Score);
    }

    [Fact] // FR16: 16 of 32 pairs definite → 50%; score null (insufficient coverage)
    public void Coverage_below_70_percent_gives_null_score()
    {
        var (s, _) = Eval(Fixtures.Host("192.168.1.20", Array.Empty<int>(), closed: 16, silent: 16));
        Assert.Equal(0.5, s.Coverage, 3);
        Assert.Null(s.Score);
    }

    [Fact] // A mostly unresponsive scan with no open ports does not produce "zero risk"
    public void Mostly_silent_scan_is_not_published_as_safe()
    {
        var (s, f) = Eval(Fixtures.Host("192.168.1.20", Array.Empty<int>(), closed: 2, silent: 30));
        var net = RiskEngine.ScoreNetwork(new[] { s }, provisional: false);
        Assert.Null(net.Score);
        Assert.Contains(f, x => x.RuleId == "R08" && x.UncertainCount == 30);
    }

    [Fact] // Adding new devices does not dilute a priority finding
    public void Adding_clean_devices_does_not_dilute_finding()
    {
        var bad = Eval(Fixtures.Host("192.168.1.20", new[] { 3389 }, closed: 31)).Score;
        var clean = Enumerable.Range(0, 10).Select(i => Eval(Fixtures.Host($"192.168.1.{30 + i}", Array.Empty<int>(), closed: 32)).Score).ToList();
        Assert.Equal(85, RiskEngine.ScoreNetwork(clean.Append(bad).ToList(), false).Score);
    }

    [Fact]
    public void No_evaluable_device_is_not_evaluable()
    {
        Assert.Equal("not_evaluable", RiskEngine.ScoreNetwork(Array.Empty<HostScore>(), false).State);
    }
}

public class ServiceEvidenceTests
{
    [Fact]
    public void Telnet_negotiation_is_verified()
    {
        var ev = new ServiceEvidence();
        ServiceProber.Interpret(23, new byte[] { 0xFF, 0xFD, 0x18, 0xFF, 0xFD, 0x20 }, ev);
        Assert.True(ev.TelnetVerified);
        Assert.Equal("banner", ev.Method);
    }

    [Fact]
    public void Ftp_greeting_is_verified()
    {
        var ev = new ServiceEvidence();
        ServiceProber.Interpret(21, "220 (vsFTPd 3.0.3)\r\n"u8.ToArray(), ev);
        Assert.True(ev.FtpVerified);
        Assert.Equal("FTP", ev.ServiceName);
    }

    [Fact] // Port 80 is not automatically confirmed as an HTTP product
    public void Port_number_alone_is_only_a_guess()
    {
        var ev = new ServiceEvidence { ServiceName = PortCatalog.ServiceName(80) };
        Assert.Equal("port_table", ev.Method);
        Assert.Null(ev.Product);
    }

    [Fact]
    public void Ssh_banner_extracts_product()
    {
        var ev = new ServiceEvidence();
        ServiceProber.Interpret(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"u8.ToArray(), ev);
        Assert.Equal("SSH", ev.ServiceName);
        Assert.Equal("OpenSSH", ev.Product);
        Assert.StartsWith("8.9", ev.Version);
    }

    [Fact] // SEC05: control characters are stripped, length is limited
    public void Banner_text_is_sanitised()
    {
        var text = SafeText.PrintableAscii(new byte[] { (byte)'<', 0x1B, (byte)'[', (byte)'3', (byte)'1', (byte)'m', 0x00, (byte)'x' }, 256);
        Assert.DoesNotContain('\u001b', text);
        Assert.Equal(10, SafeText.Clean(new string('a', 50), 10)!.Length);
    }
}

public class SessionTests
{
    [Fact] // SEC02: missing, wrong, expired and reused secrets are rejected
    public void Bootstrap_secret_rules()
    {
        var now = DateTimeOffset.UtcNow;
        var s = new SessionManager(() => now);
        Assert.Null(s.Redeem(null));
        Assert.Null(s.Redeem("wrong"));
        Assert.Null(s.Redeem(new string('A', 43)));

        var secret = s.CreateBootstrapSecret();
        Assert.Equal(43, secret.Length); // 256 bit base64url
        var token = s.Redeem(secret);
        Assert.NotNull(token);
        Assert.True(s.Validate(token));
        Assert.Null(s.Redeem(secret));

        var late = s.CreateBootstrapSecret();
        now = now.AddSeconds(61);
        Assert.Null(s.Redeem(late));

        s.RevokeAll();
        Assert.False(s.Validate(token));
    }
}

public sealed class StorageTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lanora-test-" + Guid.NewGuid().ToString("N"));
    private readonly Database _db;
    private readonly ScanStore _store;
    private readonly RiskEngine _risk = new(new Ruleset());

    public StorageTests()
    {
        _db = new Database(new AppPaths(_dir));
        _db.Initialize();
        _store = new ScanStore(_db);
    }

    private async Task<(string ScanId, string Scope)> NewScan(ScanPlan plan)
    {
        var id = Guid.NewGuid().ToString();
        var scope = await _store.CreateScanAsync(id, plan, "test", _risk.Version);
        return (id, scope);
    }

    private static ScanPlan Plan()
    {
        var a = Fixtures.Adapter();
        var t = TargetValidator.Validate(a, new[] { "192.168.1.0/24" });
        return new ScanPlan(a, t, "quick", new PortCatalog().Get("quick")!.Ports!, 800, 1, 10000, new RateSettings(), "ports-1.0");
    }

    private async Task<long> Save(string scanId, string scope, HostResult h)
    {
        var f = _risk.Evaluate(h);
        return await _store.SaveHostAsync(scanId, scope, h, f, RiskEngine.ScoreHost(h, f));
    }

    [Fact] // FR12/FR13: the label is kept when the same MAC gets a new IP; not carried over when the same IP has a different MAC
    public async Task Identity_follows_mac_not_ip()
    {
        var plan = Plan();
        var (s1, scope) = await NewScan(plan);
        await Save(s1, scope, Fixtures.Host("192.168.1.18", new[] { 80 }, closed: 31, mac: "C0:BD:D1:45:73:92"));
        var dev = _store.GetHosts(s1).Single().DeviceId!;
        await _store.UpdateDeviceAsync(dev, "Kitchen Smart TV", true, "tv", true, null, false);

        var (s2, _) = await NewScan(plan);
        await Save(s2, scope, Fixtures.Host("192.168.1.44", new[] { 80 }, closed: 31, mac: "C0:BD:D1:45:73:92"));
        await Save(s2, scope, Fixtures.Host("192.168.1.18", new[] { 80 }, closed: 31, mac: "00:11:32:4C:80:63"));
        var hosts = _store.GetHosts(s2);
        Assert.Equal("Kitchen Smart TV", hosts.Single(h => h.Ip == "192.168.1.44").Label);
        Assert.Equal("matched", hosts.Single(h => h.Ip == "192.168.1.44").IdentityStatus);
        Assert.Null(hosts.Single(h => h.Ip == "192.168.1.18").Label);

        // Two devices seen together in the same scan cannot be merged.
        var other = hosts.Single(h => h.Ip == "192.168.1.18").DeviceId!;
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => _store.MergeAsync(other, dev));
        Assert.Equal("MERGE_CONFLICT", ex.Message);

        var detail = _store.GetDevice(dev)!;
        Assert.Equal(2, detail.History.Count);
        Assert.Single(detail.LabelHistory);
    }

    [Fact] // Without a MAC the relation is uncertain
    public async Task Missing_mac_is_ambiguous()
    {
        var (s1, scope) = await NewScan(Plan());
        await Save(s1, scope, Fixtures.Host("192.168.1.50", new[] { 80 }, closed: 31));
        Assert.Equal("ambiguous", _store.GetHosts(s1).Single().IdentityStatus);
    }

    [Fact] // FR14: "Port closed" only with closed evidence; no response is a separate change
    public async Task Device_history_distinguishes_closed_from_silent()
    {
        var plan = Plan();
        var mac = "B8:CA:3A:12:90:4D";
        var (s1, scope) = await NewScan(plan);
        await Save(s1, scope, Fixtures.Host("192.168.1.10", new[] { 3389, 445 }, closed: 30, mac: mac));
        var (s2, _) = await NewScan(plan);
        var h2 = Fixtures.Host("192.168.1.10", Array.Empty<int>(), closed: 30, mac: mac);
        h2.Ports[3389] = new PortObservationResult { Protocol = "tcp", Port = 3389, State = PortState.Closed, Attempts = 1 };
        h2.Ports[445] = new PortObservationResult { Protocol = "tcp", Port = 445, State = PortState.NoResponse, Attempts = 2 };
        await Save(s2, scope, h2);
        var dev = _store.GetHosts(s2).Single().DeviceId!;
        var latest = _store.GetDevice(dev)!.History.First();
        Assert.Equal(new[] { 3389 }, latest.ClosedWithEvidence);
        Assert.Equal(new[] { 445 }, latest.NoLongerResponding);
    }

    [Fact] // FR26: deletion also removes related observations and findings
    public async Task Deleting_scan_cascades()
    {
        var (s1, scope) = await NewScan(Plan());
        await Save(s1, scope, Fixtures.Host("192.168.1.10", new[] { 3389 }, closed: 31, mac: "B8:CA:3A:12:90:4D"));
        await _store.FinishScanAsync(s1, ScanStates.Completed, null, 1, 32, null, new Dictionary<string, int?>(), _risk.Version);
        Assert.True(await _store.DeleteScanAsync(s1));
        using var c = _db.Open();
        Assert.Equal(0L, Db.Scalar<long>(c, null, "SELECT COUNT(*) FROM port_observation"));
        Assert.Equal(0L, Db.Scalar<long>(c, null, "SELECT COUNT(*) FROM finding"));
    }

    [Fact] // FR20: a cancelled scan earns no badge
    public async Task Cancelled_scan_awards_no_badge()
    {
        var badges = new BadgeService(_db);
        var (s1, scope) = await NewScan(Plan());
        await _store.FinishScanAsync(s1, ScanStates.Cancelled, "USER_CANCELLED", 0, 0, null, new Dictionary<string, int?>(), _risk.Version);
        await badges.EvaluateAsync(s1);
        Assert.All(badges.Get(scope), b => Assert.False(b.Earned));

        var (s2, _) = await NewScan(Plan());
        await _store.FinishScanAsync(s2, ScanStates.Completed, null, 0, 0, null, new Dictionary<string, int?>(), _risk.Version);
        await badges.EvaluateAsync(s2);
        Assert.True(badges.Get(scope).Single(b => b.BadgeKey == BadgeService.FirstScan).Earned);
    }

    [Fact] // FR23/FR24: PDF and XLSX are produced; values starting with = + - @ do not become formulas
    public async Task Reports_render_and_neutralise_formulas()
    {
        var plan = Plan();
        var (s1, scope) = await NewScan(plan);
        await Save(s1, scope, Fixtures.Host("192.168.1.10", new[] { 23, 3389 }, closed: 30, telnet: true, mac: "B8:CA:3A:12:90:4D"));
        var dev = _store.GetHosts(s1).Single().DeviceId!;
        await _store.UpdateDeviceAsync(dev, "=HYPERLINK(\"http://x\")", true, null, false, null, false);
        await _store.FinishScanAsync(s1, ScanStates.Completed, null, 1, 64, new NetworkScore(60, "ok", 1, 32, 32, false), new Dictionary<string, int?>(), _risk.Version);

        foreach (var lang in new[] { "tr", "en", "de" })
        {
            var hosts = _store.GetHosts(s1, allObservations: true);
            var data = new ReportData(_store.GetSummary(s1)!, hosts, null, new ReportText(lang), new Ruleset(), DateTimeOffset.Now, false);
            var pdf = PdfReport.Render(data);
            Assert.True(pdf.Length > 1000);
            Assert.Equal("%PDF", System.Text.Encoding.ASCII.GetString(pdf, 0, 4));

            var xlsx = XlsxReport.Render(data);
            using var wb = new XLWorkbook(new MemoryStream(xlsx));
            Assert.Equal(5, wb.Worksheets.Count);
            var cell = wb.Worksheet(2).Cell(2, 2);
            Assert.False(cell.HasFormula);
            Assert.StartsWith("=HYPERLINK", cell.GetString());
            Assert.Equal(XLDataType.DateTime, wb.Worksheet(1).Column(3).CellsUsed().First(c => c.Address.RowNumber == 8).DataType);
            Assert.Equal(XLDataType.Text, wb.Worksheet(2).Cell(2, 3).DataType); // IP is a text cell
        }
    }

    public void Dispose()
    {
        _db.Dispose();
        try { Directory.Delete(_dir, true); } catch { }
    }
}
