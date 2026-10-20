namespace Lanora.Scanning;

/// <summary>Connection state codes (language-independent; FR05/FR06 table).</summary>
public static class PortState
{
    public const string Open = "open";
    public const string Closed = "closed";
    public const string Filtered = "filtered";
    public const string NoResponse = "no_response";
    public const string OpenFiltered = "open_filtered";
    public const string NotTested = "not_tested";
    public const string Error = "error";

    public static bool IsDefinite(string s) => s is Open or Closed;
}

public static class ScanStates
{
    public const string Queued = "queued";
    public const string Running = "running";
    public const string Cancelling = "cancelling";
    public const string Completed = "completed";
    public const string Partial = "partial";
    public const string Failed = "failed";
    public const string Cancelled = "cancelled";
    public const string Interrupted = "interrupted";

    public static bool IsActive(string s) => s is Queued or Running or Cancelling;
}

public static class Phases
{
    public const string Discovery = "discovery";
    public const string PortScan = "port_scan";
    public const string Enrichment = "enrichment";
    public const string Scoring = "scoring";
    public const string Saving = "saving";
    public static readonly string[] All = { Discovery, PortScan, Enrichment, Scoring, Saving };
}

public sealed record ProbeResult(string State, string ReasonCode, int ElapsedMs);

public sealed class ServiceEvidence
{
    public string? ServiceName { get; set; }
    /// <summary>port_table | http_head | tls_handshake | banner</summary>
    public string Method { get; set; } = "port_table";
    public string? Product { get; set; }
    public string? Version { get; set; }
    public string? Summary { get; set; }
    public bool TelnetVerified { get; set; }
    public bool FtpVerified { get; set; }
    public string? TlsCertificateStatus { get; set; }
}

public sealed class PortObservationResult
{
    public required string Protocol { get; init; }
    public required int Port { get; init; }
    public string State { get; set; } = PortState.NotTested;
    public string ReasonCode { get; set; } = "not_attempted";
    public string Method { get; set; } = "tcp_connect";
    public DateTimeOffset ObservedAt { get; set; } = DateTimeOffset.UtcNow;
    public int Attempts { get; set; }
    public ServiceEvidence? Service { get; set; }
}

public sealed record ScriptEvidence(string Id, string Output);
public sealed record TraceHop(int Ttl, string? Ip, string? Host, double? RttMs);

public sealed class HostResult
{
    public required uint Ip { get; init; }
    public string IpText => Net.Ipv4.Format(Ip);
    public bool IsLocal { get; init; }
    public bool IsGateway { get; init; }
    public HashSet<string> DiscoveryEvidence { get; } = new();
    public int? IcmpTtl { get; set; }
    public string? Mac { get; set; }
    public string? MacSource { get; set; }
    public string? Vendor { get; set; }
    public string? TypeGuess { get; set; }
    public string? OsCandidate { get; set; }
    public string? OsSource { get; set; }
    public string? OsConfidence { get; set; }
    // Advanced scan enrichments:
    public string? Ipv6 { get; set; }
    public string? Hostname { get; set; }
    public string? HostnameType { get; set; }
    public int? Distance { get; set; }
    public List<ScriptEvidence> Scripts { get; } = new();
    public List<TraceHop> Trace { get; } = new();
    public Dictionary<int, PortObservationResult> Ports { get; } = new();
    public bool Alive => DiscoveryEvidence.Count > 0;
}

public sealed class ScanRequest
{
    public string? InterfaceId { get; set; }
    public string? NetworkScopeId { get; set; }
    public List<string>? Targets { get; set; }
    public string? ProfileId { get; set; }
    public List<int>? TcpPorts { get; set; }
    public bool IncludeUdp { get; set; }
    public bool IncludeOsDetection { get; set; }
}

public sealed record ScanPlan(
    Net.AdapterInfo Adapter,
    Net.TargetPlan Targets,
    string ProfileId,
    IReadOnlyList<int> Ports,
    int TimeoutMs,
    int Retries,
    long MaxAttempts,
    RateSettings Rate,
    string PortListVersion);
