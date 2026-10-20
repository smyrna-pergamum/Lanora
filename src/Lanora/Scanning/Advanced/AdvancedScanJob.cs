using Lanora.Infrastructure;

namespace Lanora.Scanning.Advanced;

/// <summary>Advanced scan job run by the built-in engine. Progress is derived from the engine's phase output.</summary>
public sealed class AdvancedScanJob : IScanJob
{
    public AdvancedScanJob(string id, AdvancedPlan plan, string scopeId, int targetCount)
    {
        Id = id;
        Plan = plan;
        ScopeId = scopeId;
        TargetCount = targetCount;
    }

    public string Id { get; }
    public AdvancedPlan Plan { get; }
    public string ScopeId { get; }
    public int TargetCount { get; }
    public string State { get; set; } = ScanStates.Queued;
    public double Percent { get; set; }
    public string? PhaseLabel { get; set; }
    public int HostsResponded { get; set; }
    public int OpenPorts { get; set; }
    public int Findings { get; set; }
    public string? StopReason { get; set; }
    public bool UserCancelled { get; set; }
    public DateTimeOffset StartedAt { get; } = DateTimeOffset.UtcNow;
    public CancellationTokenSource Cts { get; } = new();
    public ScanEventBuffer Events { get; } = new();
    public Task? Runner { get; set; }

    public object Progress() => new
    {
        scan_id = Id,
        state = State,
        engine = "advanced",
        phase = "advanced",
        phase_label = PhaseLabel,
        phase_index = 1,
        phase_count = 1,
        phase_percent = (int)Math.Clamp(Percent, 0, 100),
        hosts_responded = HostsResponded,
        open_ports = OpenPorts,
        findings = Findings,
        addresses_probed = TargetCount,
        started_at = Clock.Iso(StartedAt),
    };
}
