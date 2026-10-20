using Lanora.Infrastructure;

namespace Lanora.Scanning;

public sealed class RateSettings
{
    public int GlobalConcurrency { get; init; } = 64;
    public int PerHostConcurrency { get; init; } = 4;
    public int NewConnectionsPerSecond { get; init; } = 100;
    public int TimeBudgetMinutes { get; init; } = 15;
}

public sealed class ProfileDefinition
{
    public string Id { get; init; } = "";
    public string Protocol { get; init; } = "tcp";
    public int TimeoutMs { get; init; } = 1000;
    public int Retries { get; init; } = 1;
    public int[]? Ports { get; init; }
    public int? MaxPorts { get; init; }
    public int? MaxAttempts { get; init; }
    public bool? Available { get; init; }
    public string? Requires { get; init; }
    public int[]? UdpPorts { get; init; }
}

public sealed class ProfileFile
{
    public string Version { get; init; } = "";
    public RateSettings Rate { get; init; } = new();
    public List<ProfileDefinition> Profiles { get; init; } = new();
}

/// <summary>Versioned port lists and service names (estimated from the port number).</summary>
public sealed class PortCatalog
{
    private readonly ProfileFile _file;

    public PortCatalog() : this(Res.ReadJson<ProfileFile>("res/profiles.json")) { }

    public PortCatalog(ProfileFile file)
    {
        _file = file;
        foreach (var p in _file.Profiles.Where(p => p.Ports is not null))
        {
            if (p.Ports!.Distinct().Count() != p.Ports!.Length) throw new InvalidDataException($"duplicate ports in {p.Id}");
        }
    }

    public string Version => _file.Version;
    public RateSettings Rate => _file.Rate;
    public IReadOnlyList<ProfileDefinition> Profiles => _file.Profiles;
    public ProfileDefinition? Get(string id) => _file.Profiles.FirstOrDefault(p => p.Id == id);

    public static string? ServiceName(int port) => Services.TryGetValue(port, out var s) ? s : null;

    private static readonly Dictionary<int, string> Services = new()
    {
        [7] = "Echo", [9] = "Discard", [13] = "Daytime", [20] = "FTP-Data", [21] = "FTP", [22] = "SSH", [23] = "Telnet",
        [25] = "SMTP", [37] = "Time", [53] = "DNS", [79] = "Finger", [80] = "HTTP", [81] = "HTTP", [88] = "Kerberos",
        [110] = "POP3", [111] = "RPCbind", [113] = "Ident", [119] = "NNTP", [135] = "MS-RPC", [139] = "NetBIOS",
        [143] = "IMAP", [179] = "BGP", [389] = "LDAP", [427] = "SLP", [443] = "HTTPS", [444] = "HTTPS", [445] = "SMB",
        [465] = "SMTPS", [512] = "rexec", [513] = "rlogin", [514] = "rsh", [515] = "LPD", [548] = "AFP", [554] = "RTSP",
        [587] = "SMTP", [631] = "IPP", [636] = "LDAPS", [873] = "rsync", [902] = "VMware", [993] = "IMAPS", [995] = "POP3S",
        [1025] = "RPC", [1080] = "SOCKS", [1194] = "OpenVPN", [1400] = "Sonos", [1433] = "MSSQL", [1521] = "Oracle",
        [1723] = "PPTP", [1883] = "MQTT", [1900] = "UPnP", [2000] = "SCCP", [2049] = "NFS", [2082] = "cPanel",
        [2083] = "cPanel", [2121] = "FTP", [2222] = "SSH", [2375] = "Docker", [2376] = "Docker TLS", [2869] = "UPnP",
        [3000] = "HTTP", [3128] = "Proxy", [3260] = "iSCSI", [3283] = "Apple Remote", [3306] = "MySQL", [3389] = "RDP",
        [3478] = "STUN", [3689] = "DAAP", [3690] = "SVN", [4000] = "HTTP", [4443] = "HTTPS", [4567] = "HTTP",
        [5000] = "UPnP/HTTP", [5001] = "HTTPS", [5009] = "AirPort", [5060] = "SIP", [5061] = "SIP TLS", [5222] = "XMPP",
        [5357] = "WSD", [5432] = "PostgreSQL", [5555] = "ADB", [5601] = "Kibana", [5672] = "AMQP", [5800] = "VNC-HTTP",
        [5900] = "VNC", [5901] = "VNC", [5985] = "WinRM", [5986] = "WinRM TLS", [6000] = "X11", [6379] = "Redis",
        [6443] = "Kubernetes", [6667] = "IRC", [7000] = "AirPlay", [7070] = "RTSP", [7100] = "AirPlay", [7547] = "TR-069",
        [7777] = "HTTP", [8000] = "HTTP", [8001] = "HTTP", [8002] = "HTTPS", [8008] = "HTTP", [8009] = "Cast",
        [8080] = "HTTP", [8081] = "HTTP", [8088] = "HTTP", [8089] = "HTTPS", [8090] = "HTTP", [8181] = "HTTP",
        [8200] = "UPnP Media", [8291] = "Winbox", [8333] = "Bitcoin", [8443] = "HTTPS", [8883] = "MQTT TLS",
        [8888] = "HTTP", [9000] = "HTTP", [9001] = "HTTP", [9080] = "HTTP", [9090] = "HTTP", [9100] = "JetDirect",
        [9200] = "Elasticsearch", [9443] = "HTTPS", [9999] = "HTTP", [10000] = "Webmin", [10250] = "Kubelet",
        [11211] = "Memcached", [27017] = "MongoDB", [32400] = "Plex", [49152] = "UPnP", [62078] = "Apple Sync",
    };
}
