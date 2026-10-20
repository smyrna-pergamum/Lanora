using System.Text.Json;
using Lanora.Data;
using Lanora.Infrastructure;
using Lanora.Risk;
using Lanora.Scanning;

namespace Lanora.Reports;

public sealed record ReportData(
    ScanSummary Scan,
    List<HostDto> Hosts,
    JsonElement? Comparison,
    ReportText T,
    Ruleset Rules,
    DateTimeOffset GeneratedAt,
    bool Active);

/// <summary>FR25: A report is built from a specific scan_id and immutable observation data; it is never mixed with a live scan.</summary>
public sealed class ReportBuilder
{
    private readonly ScanStore _store;
    private readonly Ruleset _rules;
    private readonly ScanOrchestrator _orchestrator;

    public ReportBuilder(ScanStore store, Ruleset rules, ScanOrchestrator orchestrator)
    {
        _store = store;
        _rules = rules;
        _orchestrator = orchestrator;
    }

    public ReportData? Build(string scanId, string lang)
    {
        var summary = _store.GetSummary(scanId);
        if (summary is null) return null;
        var hosts = _store.GetHosts(scanId, allObservations: true);
        JsonElement? comparison = null;
        var prev = _store.PreviousComparable(scanId);
        if (prev is not null)
        {
            var cmp = _store.Compare(scanId, prev);
            if (cmp is not null) comparison = JsonSerializer.SerializeToElement(cmp, Json.Options);
        }
        var active = _orchestrator.Active?.Id == scanId;
        return new ReportData(summary, hosts, comparison, new ReportText(lang), _rules, DateTimeOffset.Now, active);
    }

    public static string FileName(ReportData d, string ext)
    {
        var t = Clock.Parse(d.Scan.StartedAt).ToLocalTime();
        return $"LANORA_{t:yyyyMMdd-HHmm}_{d.T.Lang}.{ext}";
    }

    public static string HostName(HostDto h, ReportText t) =>
        h.Label ?? (h.IsLocal ? t["this_computer"] : h.IsGateway ? t["gateway"] : h.Vendor ?? t["unknown"]);

    public static string VendorText(HostDto h, ReportText t) =>
        h.Vendor ?? (h.Mac is null ? "—" : h.MacKind == "local_admin" ? t["random_mac"] : t["unknown"]);

    public static string OsText(HostDto h, ReportText t) =>
        h.OsCandidate is null ? t["unknown"] : $"{h.OsCandidate} ({t.OsSource(h.OsSource)}, {t["conf." + h.OsConfidence]})";

    public static string RuleText(ReportData d, string ruleId, string part, FindingDto f)
    {
        var rule = d.Rules.Get(ruleId);
        var arr = part switch
        {
            "title" => rule.Title,
            "observed" => rule.Observed,
            "meaning" => rule.Meaning,
            "action" => rule.Action,
            _ => rule.Verify,
        };
        var s = arr.Length > d.T.Index ? arr[d.T.Index] : arr.FirstOrDefault() ?? ruleId;
        return s.Replace("{port}", f.Port.ToString(), StringComparison.Ordinal)
                .Replace("{count}", (f.UncertainCount ?? 0).ToString(), StringComparison.Ordinal);
    }

    public static string ScoreText(ScanSummary s, ReportText t)
    {
        var value = s.NetworkState switch
        {
            "ok" when s.NetworkScore is not null => $"{s.NetworkScore} / 100",
            "insufficient_coverage" => t["insufficient_coverage"],
            "not_evaluable" => t["not_evaluable"],
            _ => "—",
        };
        return s.Provisional && s.NetworkScore is not null ? $"{value} ({t["provisional"]})" : value;
    }

    public static IReadOnlyList<(string Code, int Count)> StateDistribution(ReportData d)
    {
        var codes = new[] { PortState.Open, PortState.Closed, PortState.Filtered, PortState.NoResponse, PortState.OpenFiltered, PortState.NotTested, PortState.Error };
        return codes.Select(c => (c, d.Hosts.Sum(h => h.StateCounts.TryGetValue(c, out var n) ? n : 0))).ToList();
    }
}
