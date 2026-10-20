namespace Lanora.Data;

public sealed record ScanSummary
{
    public required string Id { get; init; }
    public required string NetworkScopeId { get; init; }
    public required string NetworkCidr { get; init; }
    public string? Gateway { get; init; }
    public string? NetworkName { get; init; }
    public required string State { get; init; }
    public string? ReasonCode { get; init; }
    public required string StartedAt { get; init; }
    public string? EndedAt { get; init; }
    public required string ProfileId { get; init; }
    public int PortCount { get; init; }
    public int TargetCount { get; init; }
    public int AddressesProbed { get; init; }
    public int HostsResponded { get; init; }
    public long Attempts { get; init; }
    public required string EngineVersion { get; init; }
    public required string RulesetVersion { get; init; }
    public string? PortListVersion { get; init; }
    public int? NetworkScore { get; init; }
    public string? NetworkState { get; init; }
    public double? Coverage { get; init; }
    public int PlannedPairs { get; init; }
    public int DefinitePairs { get; init; }
    public bool Provisional { get; init; }
    public int PriorityFindings { get; init; }
    public int HighFindings { get; init; }
    public int OpenPorts { get; init; }
    public string? InterfaceName { get; init; }
    public string? InterfaceKind { get; init; }
    public string? LocalIp { get; init; }
    public bool Advanced { get; init; }
    public bool AnyExternal { get; init; }
    public string? Technique { get; init; }
}

public sealed record ObservationDto(
    long Id, string Protocol, int Port, string State, string? ReasonCode, string Method, string ObservedAt, int Attempts,
    string? ServiceName, string? ServiceMethod, string? ServiceProduct, string? ServiceVersion, string? EvidenceSummary);

public sealed record FindingDto(long Id, long? ObservationId, int Port, string Protocol, string RuleId, string Severity, int Penalty, string? Evidence, int? UncertainCount, bool Required);

public sealed record HostDto
{
    public required long Id { get; init; }
    public string? DeviceId { get; init; }
    public required string Ip { get; init; }
    public string? Mac { get; init; }
    public string? MacKind { get; init; }
    public string? Vendor { get; init; }
    public string? Label { get; init; }
    public string? UserType { get; init; }
    public string? TypeGuess { get; init; }
    public bool IsLocal { get; init; }
    public bool IsGateway { get; init; }
    public required string IdentityStatus { get; init; }
    public required string DiscoveryEvidence { get; init; }
    public string? OsCandidate { get; init; }
    public string? OsSource { get; init; }
    public string? OsConfidence { get; init; }
    public string? Hostname { get; init; }
    public string? HostnameType { get; init; }
    public string? Ipv6 { get; init; }
    public int? Distance { get; init; }
    public List<object> Scripts { get; init; } = new();
    public List<object> Trace { get; init; } = new();
    public int PlannedPairs { get; init; }
    public int DefinitePairs { get; init; }
    public double Coverage => PlannedPairs == 0 ? 0 : DefinitePairs / (double)PlannedPairs;
    public int? Score { get; init; }
    public int RawScore { get; init; }
    public int Penalty { get; init; }
    public Dictionary<string, int> StateCounts { get; init; } = new();
    public List<ObservationDto> Open { get; init; } = new();
    public List<FindingDto> Findings { get; init; } = new();
    public string? DeviceFirstSeen { get; init; }
    public string? DeviceLastSeen { get; init; }
}

public sealed record BadgeDto(string BadgeKey, bool Earned, bool Active, string? AwardedAt, string? DeactivatedAt, int? Progress, int? Goal);

public sealed record DeviceHistoryEntry(
    string ScanId, string StartedAt, string ScanState, string ProfileId, string Ip, int? Score, double Coverage,
    List<int> OpenPorts, List<int> NewlyOpened, List<int> ClosedWithEvidence, List<int> NoLongerResponding, List<int> NotMeasured);

public sealed record LabelHistoryDto(string? OldName, string? NewName, string? OldType, string? NewType, string ChangedAt);

public sealed record DeviceDetailDto
{
    public required string Id { get; init; }
    public required string NetworkScopeId { get; init; }
    public string? CustomName { get; init; }
    public string? UserType { get; init; }
    public string? Notes { get; init; }
    public string? MergedInto { get; init; }
    public required string FirstSeen { get; init; }
    public required string LastSeen { get; init; }
    public List<string> MergedDevices { get; init; } = new();
    public List<object> Identities { get; init; } = new();
    public List<LabelHistoryDto> LabelHistory { get; init; } = new();
    public List<DeviceHistoryEntry> History { get; init; } = new();
    public Dictionary<string, bool> RequiredServices { get; init; } = new();
    public List<object> MergeCandidates { get; init; } = new();
}
