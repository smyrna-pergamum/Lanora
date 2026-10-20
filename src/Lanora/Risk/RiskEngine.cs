using Lanora.Infrastructure;
using Lanora.Scanning;

namespace Lanora.Risk;

public sealed class RuleDefinition
{
    public string Id { get; init; } = "";
    public string Severity { get; init; } = "info";
    public int Penalty { get; init; }
    public string Protocol { get; init; } = "tcp";
    public int[] Ports { get; init; } = Array.Empty<int>();
    public string? RequiresEvidence { get; init; }
    public bool WhenEvidenceMissing { get; init; }
    public bool ScopeWarning { get; init; }
    public string[] Title { get; init; } = Array.Empty<string>();
    public string[] Observed { get; init; } = Array.Empty<string>();
    public string[] Meaning { get; init; } = Array.Empty<string>();
    public string[] Action { get; init; } = Array.Empty<string>();
    public string[] Verify { get; init; } = Array.Empty<string>();
}

public sealed class RulesetFile
{
    public string Version { get; init; } = "";
    public string Note { get; init; } = "";
    public List<RuleDefinition> Rules { get; init; } = new();
}

public sealed class Ruleset
{
    public Ruleset() : this(Res.ReadJson<RulesetFile>("res/ruleset.json")) { }
    public Ruleset(RulesetFile file) => File = file;

    public RulesetFile File { get; }
    public string Version => File.Version;
    public RuleDefinition Get(string id) => File.Rules.First(r => r.Id == id);

    /// <summary>Translation arrays are ordered [en, tr, de]; English is the primary and fallback language.</summary>
    public static int LangIndex(string lang) => lang switch { "tr" => 1, "de" => 2, _ => 0 };
}

public sealed record FindingResult(int Port, string Protocol, string RuleId, string Severity, int Penalty, string? Evidence, int? UncertainCount = null);

public sealed record HostScore(int Penalty, int RawScore, int? Score, double Coverage, int Planned, int Definite);

public sealed record NetworkScore(int? Score, string State, double Coverage, int Planned, int Definite, bool Provisional);

/// <summary>
/// FR15/FR16: Findings, device score and network indicator from versioned rules. For each open protocol/port the highest
/// matching penalty is applied once; the score is in 0..100; below 70% coverage the device score is null.
/// </summary>
public sealed class RiskEngine
{
    public const double MinCoverage = 0.70;
    private readonly Ruleset _rules;

    public RiskEngine(Ruleset rules) => _rules = rules;

    public string Version => _rules.Version;

    public static bool IsPriority(string severity) => severity is "high" or "medium";

    public IReadOnlyList<FindingResult> Evaluate(HostResult host)
    {
        var findings = new List<FindingResult>();
        foreach (var obs in host.Ports.Values.Where(p => p.State == PortState.Open).OrderBy(p => p.Port))
        {
            var best = Match(obs);
            findings.Add(new FindingResult(obs.Port, obs.Protocol, best.Id, best.Severity, best.Penalty, obs.Service?.Summary));
        }
        var uncertain = host.Ports.Values.Count(p => !PortState.IsDefinite(p.State));
        if (uncertain > 0)
        {
            var r08 = _rules.Get("R08");
            findings.Add(new FindingResult(0, "tcp", r08.Id, r08.Severity, r08.Penalty, null, uncertain));
        }
        return findings;
    }

    private RuleDefinition Match(PortObservationResult obs)
    {
        var generic = _rules.File.Rules.First(r => r.Id == "R07"); // generic "observed service"
        var candidates = new List<RuleDefinition>();
        foreach (var rule in _rules.File.Rules)
        {
            if (rule.ScopeWarning) continue;
            // TCP rules apply only to TCP ports; a rule is skipped if the protocol does not match.
            if (rule.Protocol != obs.Protocol) continue;
            if (rule.Ports.Length == 0)
            {
                candidates.Add(rule); // R07: other open ports
                continue;
            }
            if (!rule.Ports.Contains(obs.Port)) continue;
            var telnet = obs.Service?.TelnetVerified == true;
            var ftp = obs.Service?.FtpVerified == true;
            if (rule.RequiresEvidence == "telnet" && !telnet) continue;
            if (rule.RequiresEvidence == "ftp" && !ftp) continue;
            if (rule.WhenEvidenceMissing && ((obs.Port == 23 && telnet) || (obs.Port == 21 && ftp))) continue;
            candidates.Add(rule);
        }
        if (candidates.Count == 0) return generic; // e.g. open UDP port: informational
        // Highest penalty; on a tie, the rule with a port list (more specific) wins.
        return candidates.OrderByDescending(r => r.Penalty).ThenByDescending(r => r.Ports.Length > 0).ThenBy(r => r.Id).First();
    }

    public static HostScore ScoreHost(HostResult host, IReadOnlyList<FindingResult> findings)
    {
        var planned = host.Ports.Count;
        var definite = host.Ports.Values.Count(p => PortState.IsDefinite(p.State));
        var penalty = findings.Where(f => f.Port > 0).GroupBy(f => (f.Protocol, f.Port)).Sum(g => g.Max(f => f.Penalty));
        var raw = Math.Clamp(100 - penalty, 0, 100);
        var coverage = planned == 0 ? 0 : definite / (double)planned;
        return new HostScore(penalty, raw, coverage >= MinCoverage ? raw : null, coverage, planned, definite);
    }

    /// <summary>
    /// The network indicator is the lowest score among evaluated devices. Observed penalties of devices with insufficient
    /// coverage also count as an upper bound, so a priority finding cannot be diluted by adding new devices.
    /// If total definite-result coverage is below 70%, no numeric indicator is published.
    /// </summary>
    public static NetworkScore ScoreNetwork(IReadOnlyList<HostScore> hosts, bool provisional)
    {
        var planned = hosts.Sum(h => h.Planned);
        var definite = hosts.Sum(h => h.Definite);
        var coverage = planned == 0 ? 0 : definite / (double)planned;
        var evaluable = hosts.Where(h => h.Score is not null).ToList();
        if (evaluable.Count == 0) return new NetworkScore(null, "not_evaluable", coverage, planned, definite, provisional);
        if (coverage < MinCoverage) return new NetworkScore(null, "insufficient_coverage", coverage, planned, definite, provisional);
        var min = evaluable.Min(h => h.Score!.Value);
        foreach (var h in hosts.Where(h => h.Score is null && h.Penalty > 0)) min = Math.Min(min, h.RawScore);
        return new NetworkScore(min, "ok", coverage, planned, definite, provisional);
    }
}
