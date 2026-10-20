using Lanora.Infrastructure;

namespace Lanora.Scanning;

public sealed record ScanEvent(long Id, string Type, string Data);

/// <summary>Bounded event buffer with sequential event_id. On overflow the client is told to fetch the current snapshot.</summary>
public sealed class ScanEventBuffer
{
    private const int Capacity = 5000;
    private readonly LinkedList<ScanEvent> _events = new();
    private readonly object _gate = new();
    private long _nextId = 1;
    private TaskCompletionSource _signal = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public bool Finished { get; private set; }

    public void Publish(string type, object payload, bool finish = false)
    {
        TaskCompletionSource toSignal;
        lock (_gate)
        {
            var e = new ScanEvent(_nextId++, type, Json.Serialize(payload));
            _events.AddLast(e);
            while (_events.Count > Capacity) _events.RemoveFirst();
            if (finish) Finished = true;
            toSignal = _signal;
            _signal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        toSignal.TrySetResult();
    }

    /// <summary>Events after lastId. Returns gap=true if events were lost.</summary>
    public (List<ScanEvent> Events, bool Gap, Task Next) After(long lastId)
    {
        lock (_gate)
        {
            var first = _events.First?.Value.Id ?? _nextId;
            var gap = lastId > 0 && lastId < first - 1;
            return (_events.Where(e => e.Id > lastId).ToList(), gap, _signal.Task);
        }
    }
}

/// <summary>Common surface of quick and advanced scan jobs for the orchestrator.</summary>
public interface IScanJob
{
    string Id { get; }
    string State { get; set; }
    bool UserCancelled { get; set; }
    string? StopReason { get; set; }
    CancellationTokenSource Cts { get; }
    ScanEventBuffer Events { get; }
    Task? Runner { get; set; }
    object Progress();
}

public sealed class ScanJob : IScanJob
{
    public ScanJob(string id, ScanPlan plan, string scopeId)
    {
        Id = id;
        Plan = plan;
        ScopeId = scopeId;
    }

    public string Id { get; }
    public ScanPlan Plan { get; }
    public string ScopeId { get; }
    public string State { get; set; } = ScanStates.Queued;
    public string Phase { get; set; } = Phases.Discovery;
    public long PhaseTotal;
    public long PhaseDone;
    public long Attempts;
    public int HostsResponded;
    public int OpenPorts;
    public int Findings;
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
        phase = Phase,
        phase_index = Array.IndexOf(Phases.All, Phase) + 1,
        phase_count = Phases.All.Length,
        phase_done = Interlocked.Read(ref PhaseDone),
        phase_total = Interlocked.Read(ref PhaseTotal),
        phase_percent = PhaseTotal == 0 ? 0 : (int)Math.Min(100, Interlocked.Read(ref PhaseDone) * 100 / Math.Max(1, Interlocked.Read(ref PhaseTotal))),
        attempts = Interlocked.Read(ref Attempts),
        hosts_responded = HostsResponded,
        open_ports = OpenPorts,
        findings = Findings,
        addresses_probed = Plan.Targets.Targets.Count,
        started_at = Clock.Iso(StartedAt),
    };
}
