using System.Text.Json;
using Lanora.Infrastructure;
using Lanora.Net;
using Lanora.Risk;
using Lanora.Scanning;
using Microsoft.Data.Sqlite;

namespace Lanora.Data;

/// <summary>Scan records, observations, findings and queries. Records are immutable snapshots (FR22).</summary>
public sealed class ScanStore
{
    private readonly Database _db;

    public ScanStore(Database db) => _db = db;

    // ---------- Yazma ----------

    public Task<string> CreateScanAsync(string scanId, ScanPlan plan, string engineVersion, string rulesetVersion) =>
        _db.WriteAsync((c, tx) =>
        {
            var scope = DeviceRegistry.EnsureScope(c, tx, plan.Adapter);
            Db.Exec(c, tx, """
                INSERT INTO scan(id, network_scope_id, state, started_at, profile_id, profile_snapshot, target_snapshot, interface_snapshot,
                                 rate_snapshot, engine_version, ruleset_version, addresses_probed)
                VALUES ($id,$scope,'queued',$t,$p,$ps,$ts,$is,$rs,$e,$r,$n)
                """,
                ("$id", scanId), ("$scope", scope), ("$t", Clock.NowIso()), ("$p", plan.ProfileId),
                ("$ps", Json.Serialize(new { profile_id = plan.ProfileId, port_list_version = plan.PortListVersion, protocol = "tcp", method = "tcp_connect", ports = plan.Ports, timeout_ms = plan.TimeoutMs, retries = plan.Retries, max_attempts = plan.MaxAttempts })),
                ("$ts", Json.Serialize(new { targets = plan.Targets.Targets.Select(Ipv4.Format), excluded = plan.Targets.Excluded, local_ip = Ipv4.Format(plan.Targets.LocalIp), gateway = plan.Targets.Gateway is { } g ? Ipv4.Format(g) : null })),
                ("$is", Json.Serialize(new { id = plan.Adapter.Id, name = plan.Adapter.Name, description = plan.Adapter.Description, kind = plan.Adapter.Kind, ip = plan.Adapter.Ip, prefix = plan.Adapter.PrefixLength, network = plan.Adapter.NetworkCidr, gateway = plan.Adapter.Gateway })),
                ("$rs", Json.Serialize(plan.Rate)), ("$e", engineVersion), ("$r", rulesetVersion), ("$n", plan.Targets.Targets.Count));
            return scope;
        });

    /// <summary>Advanced scan record. The snapshot carries the option summary and resolved targets.</summary>
    public Task<string> CreateAdvancedScanAsync(string scanId, Scanning.Advanced.AdvancedPlan plan, Net.AdapterInfo? adapter, string engineVersion, string rulesetVersion, object optionSummary) =>
        _db.WriteAsync((c, tx) =>
        {
            // External/hostname scans may not belong to an adapter's network; a virtual scope key is used.
            string scope;
            if (adapter is { Selectable: true } && !plan.AnyExternal)
                scope = DeviceRegistry.EnsureScope(c, tx, adapter);
            else
                scope = EnsureExternalScope(c, tx, adapter);

            Db.Exec(c, tx, """
                INSERT INTO scan(id, network_scope_id, state, started_at, profile_id, profile_snapshot, target_snapshot, interface_snapshot,
                                 rate_snapshot, engine_version, ruleset_version, addresses_probed)
                VALUES ($id,$scope,'queued',$t,'advanced',$ps,$ts,$is,$rs,$e,$r,$n)
                """,
                ("$id", scanId), ("$scope", scope), ("$t", Clock.NowIso()),
                ("$ps", Json.Serialize(optionSummary)),
                ("$ts", Json.Serialize(new { targets = plan.Targets.Select(t => new { input = t.Input, resolved = t.Resolved, local = t.IsLocal, external = t.IsExternal, hostname = t.IsHostname }), any_external = plan.AnyExternal })),
                ("$is", Json.Serialize(adapter is null ? new { kind = "advanced", external = plan.AnyExternal } : new { id = adapter.Id, name = adapter.Name, kind = adapter.Kind, ip = adapter.Ip, network = adapter.NetworkCidr, gateway = adapter.Gateway, external = plan.AnyExternal } as object)),
                ("$rs", Json.Serialize(new { engine = "advanced" })), ("$e", engineVersion), ("$r", rulesetVersion), ("$n", plan.Targets.Count));
            return scope;
        });

    private static string EnsureExternalScope(Microsoft.Data.Sqlite.SqliteConnection c, Microsoft.Data.Sqlite.SqliteTransaction tx, Net.AdapterInfo? adapter)
    {
        var guid = adapter?.AdapterGuid ?? "{advanced}";
        var cidr = "advanced-scan";
        var id = Db.Scalar<string>(c, tx, "SELECT id FROM network_scope WHERE adapter_guid=$g AND network_cidr=$n", ("$g", guid), ("$n", cidr));
        if (id is not null) return id;
        id = Guid.NewGuid().ToString();
        Db.Exec(c, tx, "INSERT INTO network_scope(id, adapter_guid, network_cidr, gateway_identity, user_name, created_at) VALUES ($i,$g,$n,NULL,$name,$t)",
            ("$i", id), ("$g", guid), ("$n", cidr), ("$name", "Advanced scan"), ("$t", Clock.NowIso()));
        return id;
    }

    public Task SetStateAsync(string scanId, string state) =>
        _db.WriteAsync((c, tx) => { Db.Exec(c, tx, "UPDATE scan SET state=$s WHERE id=$id", ("$s", state), ("$id", scanId)); });

    public Task<long> SaveHostAsync(string scanId, string scopeId, HostResult h, IReadOnlyList<FindingResult> findings, HostScore score) =>
        _db.WriteAsync((c, tx) =>
        {
            var now = Clock.NowIso();
            var dev = DeviceRegistry.Resolve(c, tx, scopeId, h, now);
            var hostId = Db.Insert(c, tx, """
                INSERT INTO scan_host(scan_id, device_id, ip, mac_snapshot, mac_kind, vendor_snapshot, label_snapshot, type_snapshot, type_guess,
                    is_local, is_gateway, identity_status, discovery_evidence, icmp_ttl, os_candidate, os_source, os_confidence,
                    planned_pairs, definite_pairs, score, raw_score, penalty, hostname, hostname_type, ipv6, distance, scripts_json, trace_json)
                VALUES ($s,$d,$ip,$mac,$mk,$v,$l,$ut,$tg,$loc,$gw,$is,$de,$ttl,$os,$oss,$osc,$pp,$dp,$sc,$raw,$pen,$hn,$hnt,$v6,$dist,$scr,$tr)
                """,
                ("$s", scanId), ("$d", dev.DeviceId), ("$ip", h.IpText), ("$mac", h.Mac), ("$mk", dev.MacKind), ("$v", h.Vendor),
                ("$l", dev.Label), ("$ut", dev.UserType), ("$tg", h.TypeGuess), ("$loc", h.IsLocal ? 1 : 0), ("$gw", h.IsGateway ? 1 : 0),
                ("$is", dev.IdentityStatus), ("$de", string.Join(',', h.DiscoveryEvidence.Order())), ("$ttl", h.IcmpTtl),
                ("$os", h.OsCandidate), ("$oss", h.OsSource), ("$osc", h.OsConfidence),
                ("$pp", score.Planned), ("$dp", score.Definite), ("$sc", score.Score), ("$raw", score.RawScore), ("$pen", score.Penalty),
                ("$hn", h.Hostname), ("$hnt", h.HostnameType), ("$v6", h.Ipv6), ("$dist", h.Distance),
                ("$scr", h.Scripts.Count > 0 ? Json.Serialize(h.Scripts) : null), ("$tr", h.Trace.Count > 0 ? Json.Serialize(h.Trace) : null));

            var obsIds = new Dictionary<(string, int), long>();
            foreach (var o in h.Ports.Values.OrderBy(p => p.Port))
            {
                var id = Db.Insert(c, tx, """
                    INSERT INTO port_observation(scan_host_id, protocol, port, state, reason_code, method, observed_at, attempts,
                        service_name, service_method, service_product, service_version, evidence_summary, raw_state)
                    VALUES ($h,$p,$port,$st,$rc,$m,$t,$a,$sn,$sm,$sp,$sv,$ev,NULL)
                    """,
                    ("$h", hostId), ("$p", o.Protocol), ("$port", o.Port), ("$st", o.State), ("$rc", o.ReasonCode), ("$m", o.Method),
                    ("$t", Clock.Iso(o.ObservedAt)), ("$a", o.Attempts),
                    ("$sn", o.Service?.ServiceName ?? (o.State == PortState.Open ? PortCatalog.ServiceName(o.Port) : null)),
                    ("$sm", o.Service?.Method ?? (o.State == PortState.Open ? "port_table" : null)),
                    ("$sp", o.Service?.Product), ("$sv", o.Service?.Version), ("$ev", SafeText.Clean(o.Service?.Summary, 512)));
                obsIds[(o.Protocol, o.Port)] = id;
            }

            foreach (var f in findings)
            {
                long? obsId = f.Port > 0 && obsIds.TryGetValue((f.Protocol, f.Port), out var oid) ? oid : null;
                Db.Exec(c, tx, """
                    INSERT INTO finding(scan_host_id, observation_id, rule_id, severity, penalty, recommendation_key, evidence_reference, uncertain_count)
                    VALUES ($h,$o,$r,$s,$p,$k,$e,$u)
                    """,
                    ("$h", hostId), ("$o", obsId), ("$r", f.RuleId), ("$s", f.Severity), ("$p", f.Penalty), ("$k", "rule." + f.RuleId),
                    ("$e", SafeText.Clean(f.Evidence, 512)), ("$u", f.UncertainCount));
            }
            return hostId;
        });

    public Task FinishScanAsync(string scanId, string state, string? reason, int responded, long attempts, NetworkScore? net, IReadOnlyDictionary<string, int?> hostScores, string rulesetVersion) =>
        _db.WriteAsync((c, tx) =>
        {
            var now = Clock.NowIso();
            Db.Exec(c, tx, "UPDATE scan SET state=$s, reason_code=$r, ended_at=$t, hosts_responded=$h, attempts=$a WHERE id=$id",
                ("$s", state), ("$r", reason), ("$t", now), ("$h", responded), ("$a", attempts), ("$id", scanId));
            if (net is not null)
            {
                Db.Exec(c, tx, """
                    INSERT OR REPLACE INTO score_snapshot(scan_id, scope, host_scores, network_score, network_state, coverage, planned_pairs, definite_pairs, provisional, calculated_at, ruleset_version)
                    VALUES ($id,'selected_ports',$hs,$ns,$st,$cov,$pp,$dp,$prov,$t,$rv)
                    """,
                    ("$id", scanId), ("$hs", Json.Serialize(hostScores)), ("$ns", net.Score), ("$st", net.State), ("$cov", net.Coverage),
                    ("$pp", net.Planned), ("$dp", net.Definite), ("$prov", net.Provisional ? 1 : 0), ("$t", now), ("$rv", rulesetVersion));
            }
        });

    // ---------- Okuma ----------

    private const string SummarySelect = """
        SELECT s.*, ns.network_cidr, ns.gateway_identity, ns.user_name,
               ss.network_score, ss.network_state, ss.coverage, ss.planned_pairs, ss.definite_pairs, ss.provisional,
               (SELECT COUNT(*) FROM finding f JOIN scan_host h ON h.id=f.scan_host_id WHERE h.scan_id=s.id AND f.severity IN ('high','medium')) AS prio,
               (SELECT COUNT(*) FROM finding f JOIN scan_host h ON h.id=f.scan_host_id WHERE h.scan_id=s.id AND f.severity='high') AS high,
               (SELECT COUNT(*) FROM port_observation o JOIN scan_host h ON h.id=o.scan_host_id WHERE h.scan_id=s.id AND o.state='open') AS open_ports
        FROM scan s
        JOIN network_scope ns ON ns.id=s.network_scope_id
        LEFT JOIN score_snapshot ss ON ss.scan_id=s.id
        """;

    private static ScanSummary MapSummary(SqliteDataReader r)
    {
        using var profile = JsonDocument.Parse(r.Str("profile_snapshot") ?? "{}");
        using var targets = JsonDocument.Parse(r.Str("target_snapshot") ?? "{}");
        using var iface = JsonDocument.Parse(r.Str("interface_snapshot") ?? "{}");
        var p = profile.RootElement;
        return new ScanSummary
        {
            Id = r.Str("id")!,
            NetworkScopeId = r.Str("network_scope_id")!,
            NetworkCidr = r.Str("network_cidr")!,
            Gateway = r.Str("gateway_identity"),
            NetworkName = r.Str("user_name"),
            State = r.Str("state")!,
            ReasonCode = r.Str("reason_code"),
            StartedAt = r.Str("started_at")!,
            EndedAt = r.Str("ended_at"),
            ProfileId = r.Str("profile_id")!,
            PortCount = p.TryGetProperty("ports", out var ports) && ports.ValueKind == JsonValueKind.Array ? ports.GetArrayLength()
                : (p.TryGetProperty("tcp_port_count", out var tpc) && tpc.ValueKind == JsonValueKind.Number ? tpc.GetInt32() : 0)
                  + (p.TryGetProperty("udp_port_count", out var upc) && upc.ValueKind == JsonValueKind.Number ? upc.GetInt32() : 0),
            PortListVersion = p.TryGetProperty("port_list_version", out var plv) ? plv.GetString() : null,
            TargetCount = targets.RootElement.TryGetProperty("targets", out var t) ? t.GetArrayLength() : 0,
            AddressesProbed = r.Int("addresses_probed") ?? 0,
            HostsResponded = r.Int("hosts_responded") ?? 0,
            Attempts = r.Long("attempts") ?? 0,
            EngineVersion = r.Str("engine_version")!,
            RulesetVersion = r.Str("ruleset_version")!,
            NetworkScore = r.Int("network_score"),
            NetworkState = r.Str("network_state"),
            Coverage = r.Dbl("coverage"),
            PlannedPairs = r.Int("planned_pairs") ?? 0,
            DefinitePairs = r.Int("definite_pairs") ?? 0,
            Provisional = r.Bool("provisional"),
            PriorityFindings = r.Int("prio") ?? 0,
            HighFindings = r.Int("high") ?? 0,
            OpenPorts = r.Int("open_ports") ?? 0,
            InterfaceName = iface.RootElement.TryGetProperty("name", out var n) ? n.GetString() : null,
            InterfaceKind = iface.RootElement.TryGetProperty("kind", out var k) ? k.GetString() : null,
            LocalIp = iface.RootElement.TryGetProperty("ip", out var ip) ? ip.GetString() : null,
            Advanced = r.Str("profile_id") == "advanced",
            AnyExternal = targets.RootElement.TryGetProperty("any_external", out var ae) && ae.ValueKind == JsonValueKind.True,
            Technique = p.TryGetProperty("technique", out var tq) ? tq.GetString() : null,
        };
    }

    public ScanSummary? GetSummary(string scanId)
    {
        using var c = _db.Open();
        return Db.Query(c, null, SummarySelect + " WHERE s.id=$id", MapSummary, ("$id", scanId)).FirstOrDefault();
    }

    public (List<ScanSummary> Items, int Total) ListScans(string? scopeId, string? from, string? to, int page, int size)
    {
        using var c = _db.Open();
        var where = " WHERE ($scope IS NULL OR s.network_scope_id=$scope) AND ($from IS NULL OR s.started_at >= $from) AND ($to IS NULL OR s.started_at < $to)";
        var ps = new (string, object?)[] { ("$scope", scopeId), ("$from", from), ("$to", to), ("$lim", size), ("$off", (page - 1) * size) };
        var total = Db.Scalar<long>(c, null, "SELECT COUNT(*) FROM scan s" + where, ps);
        var items = Db.Query(c, null, SummarySelect + where + " ORDER BY s.started_at DESC LIMIT $lim OFFSET $off", MapSummary, ps);
        return (items, (int)total);
    }

    public List<object> ListScopes()
    {
        using var c = _db.Open();
        return Db.Query<object>(c, null, """
            SELECT ns.id, ns.network_cidr, ns.gateway_identity, ns.user_name, COUNT(s.id) AS scans, MAX(s.started_at) AS last_scan
            FROM network_scope ns LEFT JOIN scan s ON s.network_scope_id=ns.id GROUP BY ns.id ORDER BY last_scan DESC
            """, r => new { id = r.Str("id"), network_cidr = r.Str("network_cidr"), gateway = r.Str("gateway_identity"), name = r.Str("user_name"), scans = r.Long("scans"), last_scan = r.Str("last_scan") });
    }

    /// <summary>Scan shown on the dashboard: the latest completed one, otherwise the latest scan with results.</summary>
    public string? LatestDisplayScan(string? scopeId)
    {
        using var c = _db.Open();
        return Db.Scalar<string>(c, null, """
            SELECT id FROM scan WHERE ($scope IS NULL OR network_scope_id=$scope) AND state='completed' ORDER BY started_at DESC LIMIT 1
            """, ("$scope", scopeId))
            ?? Db.Scalar<string>(c, null, """
            SELECT s.id FROM scan s WHERE ($scope IS NULL OR s.network_scope_id=$scope) AND EXISTS(SELECT 1 FROM scan_host h WHERE h.scan_id=s.id) ORDER BY s.started_at DESC LIMIT 1
            """, ("$scope", scopeId));
    }

    public string? LatestScan(string? scopeId)
    {
        using var c = _db.Open();
        return Db.Scalar<string>(c, null, "SELECT id FROM scan WHERE ($scope IS NULL OR network_scope_id=$scope) ORDER BY started_at DESC LIMIT 1", ("$scope", scopeId));
    }

    public List<HostDto> GetHosts(string scanId, bool allObservations = false)
    {
        using var c = _db.Open();
        var hosts = Db.Query(c, null, """
            SELECT h.*, d.custom_name, d.user_type, d.merged_into, d.first_seen, d.last_seen
            FROM scan_host h LEFT JOIN device d ON d.id=h.device_id
            WHERE h.scan_id=$s ORDER BY h.is_gateway DESC, h.is_local DESC, h.id
            """, r => (Row: r.Long("id")!.Value, Dto: new HostDto
        {
            Id = r.Long("id")!.Value,
            DeviceId = r.Str("device_id"),
            Ip = r.Str("ip")!,
            Mac = r.Str("mac_snapshot"),
            MacKind = r.Str("mac_kind"),
            Vendor = r.Str("vendor_snapshot"),
            Label = r.Str("custom_name"),
            UserType = r.Str("user_type"),
            TypeGuess = r.Str("type_guess"),
            IsLocal = r.Bool("is_local"),
            IsGateway = r.Bool("is_gateway"),
            IdentityStatus = r.Str("identity_status")!,
            DiscoveryEvidence = r.Str("discovery_evidence")!,
            OsCandidate = r.Str("os_candidate"),
            OsSource = r.Str("os_source"),
            OsConfidence = r.Str("os_confidence"),
            Hostname = r.Str("hostname"),
            HostnameType = r.Str("hostname_type"),
            Ipv6 = r.Str("ipv6"),
            Distance = r.Int("distance"),
            Scripts = ParseJsonArray(r.Str("scripts_json")),
            Trace = ParseJsonArray(r.Str("trace_json")),
            PlannedPairs = r.Int("planned_pairs") ?? 0,
            DefinitePairs = r.Int("definite_pairs") ?? 0,
            Score = r.Int("score"),
            RawScore = r.Int("raw_score") ?? 0,
            Penalty = r.Int("penalty") ?? 0,
            DeviceFirstSeen = r.Str("first_seen"),
            DeviceLastSeen = r.Str("last_seen"),
        }), ("$s", scanId));

        var byId = hosts.ToDictionary(h => h.Row, h => h.Dto);
        foreach (var (hostId, state, count) in Db.Query(c, null, """
            SELECT o.scan_host_id, o.state, COUNT(*) AS n FROM port_observation o JOIN scan_host h ON h.id=o.scan_host_id
            WHERE h.scan_id=$s GROUP BY o.scan_host_id, o.state
            """, r => (r.Long("scan_host_id")!.Value, r.Str("state")!, r.Int("n")!.Value), ("$s", scanId)))
        {
            byId[hostId].StateCounts[state] = count;
        }

        var obsSql = """
            SELECT o.* FROM port_observation o JOIN scan_host h ON h.id=o.scan_host_id WHERE h.scan_id=$s
            """ + (allObservations ? "" : " AND o.state='open'") + " ORDER BY o.port";
        foreach (var (hostId, dto) in Db.Query(c, null, obsSql, r => (r.Long("scan_host_id")!.Value, MapObs(r)), ("$s", scanId)))
            byId[hostId].Open.Add(dto);

        var required = RequiredFlags(c, hosts.Select(h => h.Dto.DeviceId).OfType<string>().Distinct().ToList());
        foreach (var (hostId, f) in Db.Query(c, null, """
            SELECT f.*, o.port, o.protocol FROM finding f JOIN scan_host h ON h.id=f.scan_host_id LEFT JOIN port_observation o ON o.id=f.observation_id
            WHERE h.scan_id=$s ORDER BY f.penalty DESC, o.port
            """, r => (r.Long("scan_host_id")!.Value, (r.Long("id")!.Value, r.Long("observation_id"), r.Int("port") ?? 0, r.Str("protocol") ?? "tcp",
                       r.Str("rule_id")!, r.Str("severity")!, r.Int("penalty") ?? 0, r.Str("evidence_reference"), r.Int("uncertain_count"))), ("$s", scanId)))
        {
            var dev = byId[hostId].DeviceId;
            var req = dev is not null && required.TryGetValue(dev, out var set) && set.Contains($"{f.Item4}/{f.Item3}");
            byId[hostId].Findings.Add(new FindingDto(f.Item1, f.Item2, f.Item3, f.Item4, f.Item5, f.Item6, f.Item7, f.Item8, f.Item9, req));
        }
        return hosts.Select(h => h.Dto).ToList();
    }

    private static List<object> ParseJsonArray(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try
        {
            var el = JsonDocument.Parse(json).RootElement;
            return el.ValueKind == JsonValueKind.Array ? el.EnumerateArray().Select(x => (object)x.Clone()).ToList() : new();
        }
        catch { return new(); }
    }

    private static ObservationDto MapObs(SqliteDataReader r) => new(
        r.Long("id")!.Value, r.Str("protocol")!, r.Int("port")!.Value, r.Str("state")!, r.Str("reason_code"), r.Str("method")!,
        r.Str("observed_at")!, r.Int("attempts") ?? 0, r.Str("service_name"), r.Str("service_method"), r.Str("service_product"),
        r.Str("service_version"), r.Str("evidence_summary"));

    private static Dictionary<string, HashSet<string>> RequiredFlags(SqliteConnection c, List<string> deviceIds)
    {
        var map = new Dictionary<string, HashSet<string>>();
        foreach (var id in deviceIds)
        {
            var root = DeviceRegistry.ResolveRoot(c, null, id);
            var set = Db.Query(c, null, "SELECT protocol, port FROM device_service_flag WHERE device_id=$d AND required=1",
                r => $"{r.Str("protocol")}/{r.Int("port")}", ("$d", root)).ToHashSet();
            map[id] = set;
        }
        return map;
    }

    // ---------- Devices ----------

    public DeviceDetailDto? GetDevice(string deviceId)
    {
        using var c = _db.Open();
        var exists = Db.Scalar<string>(c, null, "SELECT id FROM device WHERE id=$d", ("$d", deviceId));
        if (exists is null) return null;
        var root = DeviceRegistry.ResolveRoot(c, null, deviceId);
        var members = Db.Query(c, null, "SELECT id FROM device WHERE id=$d OR merged_into=$d", r => r.Str("id")!, ("$d", root));

        var dev = Db.Query(c, null, "SELECT * FROM device WHERE id=$d", r => new
        {
            Id = r.Str("id")!, Scope = r.Str("network_scope_id")!, Name = r.Str("custom_name"), Type = r.Str("user_type"),
            Notes = r.Str("notes"), First = r.Str("first_seen")!, Last = r.Str("last_seen")!,
        }, ("$d", root)).Single();

        var inList = string.Join(',', members.Select((_, i) => "$m" + i));
        var mParams = members.Select((m, i) => ("$m" + i, (object?)m)).ToArray();

        var firstSeen = Db.Scalar<string>(c, null, $"SELECT MIN(first_seen) FROM device WHERE id IN ({inList})", mParams) ?? dev.First;
        var lastSeen = Db.Scalar<string>(c, null, $"SELECT MAX(last_seen) FROM device WHERE id IN ({inList})", mParams) ?? dev.Last;

        var identities = Db.Query<object>(c, null, $"SELECT * FROM device_identity WHERE device_id IN ({inList}) ORDER BY id",
            r => new { device_id = r.Str("device_id"), kind = r.Str("kind"), value = r.Str("value"), confidence = r.Str("confidence"), valid_from = r.Str("valid_from"), valid_to = r.Str("valid_to"), source = r.Str("source") }, mParams);

        var labels = Db.Query(c, null, $"SELECT * FROM device_label_history WHERE device_id IN ({inList}) ORDER BY changed_at DESC",
            r => new LabelHistoryDto(r.Str("old_name"), r.Str("new_name"), r.Str("old_type"), r.Str("new_type"), r.Str("changed_at")!), mParams);

        var required = Db.Query(c, null, "SELECT protocol, port, required FROM device_service_flag WHERE device_id=$d",
            r => ($"{r.Str("protocol")}/{r.Int("port")}", r.Bool("required")), ("$d", root)).ToDictionary(x => x.Item1, x => x.Item2);

        // Observation history: this device's port states in each scan.
        var scans = Db.Query(c, null, $"""
            SELECT h.id AS host_id, h.ip, h.score, h.planned_pairs, h.definite_pairs, s.id AS scan_id, s.started_at, s.state, s.profile_id
            FROM scan_host h JOIN scan s ON s.id=h.scan_id WHERE h.device_id IN ({inList}) ORDER BY s.started_at
            """, r => new
        {
            HostId = r.Long("host_id")!.Value, Ip = r.Str("ip")!, Score = r.Int("score"), Planned = r.Int("planned_pairs") ?? 0, Definite = r.Int("definite_pairs") ?? 0,
            ScanId = r.Str("scan_id")!, Started = r.Str("started_at")!, State = r.Str("state")!, Profile = r.Str("profile_id")!,
        }, mParams);

        var history = new List<DeviceHistoryEntry>();
        Dictionary<int, string>? previous = null;
        foreach (var s in scans)
        {
            var states = Db.Query(c, null, "SELECT port, state FROM port_observation WHERE scan_host_id=$h AND protocol='tcp'",
                r => (r.Int("port")!.Value, r.Str("state")!), ("$h", s.HostId)).ToDictionary(x => x.Item1, x => x.Item2);
            var open = states.Where(kv => kv.Value == PortState.Open).Select(kv => kv.Key).Order().ToList();
            var newly = new List<int>();
            var closed = new List<int>();
            var silent = new List<int>();
            var notMeasured = new List<int>();
            if (previous is not null)
            {
                newly = open.Where(p => !previous.TryGetValue(p, out var ps) || ps != PortState.Open).ToList();
                foreach (var p in previous.Where(kv => kv.Value == PortState.Open).Select(kv => kv.Key).Order())
                {
                    if (!states.TryGetValue(p, out var now) || now == PortState.NotTested) notMeasured.Add(p);
                    else if (now == PortState.Closed) closed.Add(p);   // "Port closed" only with closed evidence
                    else if (now != PortState.Open) silent.Add(p);      // No response is a separate change
                }
            }
            history.Add(new DeviceHistoryEntry(s.ScanId, s.Started, s.State, s.Profile, s.Ip, s.Score,
                s.Planned == 0 ? 0 : s.Definite / (double)s.Planned, open, newly, closed, silent, notMeasured));
            previous = states;
        }
        history.Reverse();

        var candidates = Db.Query<object>(c, null, """
            SELECT d.id, d.custom_name, (SELECT ip FROM scan_host WHERE device_id=d.id ORDER BY id DESC LIMIT 1) AS ip,
                   (SELECT mac_snapshot FROM scan_host WHERE device_id=d.id ORDER BY id DESC LIMIT 1) AS mac, d.last_seen
            FROM device d WHERE d.network_scope_id=$s AND d.merged_into IS NULL AND d.id<>$d ORDER BY d.last_seen DESC LIMIT 50
            """, r => new { id = r.Str("id"), name = r.Str("custom_name"), ip = r.Str("ip"), mac = r.Str("mac"), last_seen = r.Str("last_seen") },
            ("$s", dev.Scope), ("$d", root));

        return new DeviceDetailDto
        {
            Id = root,
            NetworkScopeId = dev.Scope,
            CustomName = dev.Name,
            UserType = dev.Type,
            Notes = dev.Notes,
            FirstSeen = firstSeen,
            LastSeen = lastSeen,
            MergedDevices = members.Where(m => m != root).ToList(),
            Identities = identities,
            LabelHistory = labels,
            History = history,
            RequiredServices = required,
            MergeCandidates = candidates,
        };
    }

    public Task<string> UpdateDeviceAsync(string deviceId, string? name, bool setName, string? type, bool setType, string? notes, bool setNotes) =>
        _db.WriteAsync((c, tx) =>
        {
            var root = DeviceRegistry.ResolveRoot(c, tx, deviceId);
            var cur = Db.Query(c, tx, "SELECT custom_name, user_type FROM device WHERE id=$d", r => (r.Str("custom_name"), r.Str("user_type")), ("$d", root)).Single();
            var newName = setName ? name : cur.Item1;
            var newType = setType ? type : cur.Item2;
            if (newName != cur.Item1 || newType != cur.Item2)
            {
                Db.Exec(c, tx, "UPDATE device SET custom_name=$n, user_type=$t WHERE id=$d", ("$n", newName), ("$t", newType), ("$d", root));
                Db.Exec(c, tx, "INSERT INTO device_label_history(device_id, old_name, new_name, old_type, new_type, changed_at) VALUES ($d,$on,$nn,$ot,$nt,$t)",
                    ("$d", root), ("$on", cur.Item1), ("$nn", newName), ("$ot", cur.Item2), ("$nt", newType), ("$t", Clock.NowIso()));
            }
            if (setNotes) Db.Exec(c, tx, "UPDATE device SET notes=$n WHERE id=$d", ("$n", notes), ("$d", root));
            return root;
        });

    /// <summary>FR13: Explicit merge. Two records seen together in the same scan cannot be merged. Reversible.</summary>
    public Task<string> MergeAsync(string deviceId, string targetId) =>
        _db.WriteAsync((c, tx) =>
        {
            var src = DeviceRegistry.ResolveRoot(c, tx, deviceId);
            var dst = DeviceRegistry.ResolveRoot(c, tx, targetId);
            if (src == dst) throw new InvalidOperationException("MERGE_SAME_DEVICE");
            var scopes = Db.Query(c, tx, "SELECT DISTINCT network_scope_id FROM device WHERE id IN ($a,$b)", r => r.Str("network_scope_id"), ("$a", src), ("$b", dst));
            if (scopes.Count != 1) throw new InvalidOperationException("MERGE_SCOPE_MISMATCH");
            var together = Db.Scalar<long>(c, tx, """
                SELECT COUNT(*) FROM scan_host a JOIN scan_host b ON a.scan_id=b.scan_id
                WHERE a.device_id IN (SELECT id FROM device WHERE id=$a OR merged_into=$a)
                  AND b.device_id IN (SELECT id FROM device WHERE id=$b OR merged_into=$b)
                """, ("$a", src), ("$b", dst));
            if (together > 0) throw new InvalidOperationException("MERGE_CONFLICT");
            Db.Exec(c, tx, "UPDATE device SET merged_into=$b WHERE merged_into=$a", ("$a", src), ("$b", dst));
            Db.Exec(c, tx, "UPDATE device SET merged_into=$b WHERE id=$a", ("$a", src), ("$b", dst));
            return dst;
        });

    public Task UnmergeAsync(string deviceId) =>
        _db.WriteAsync((c, tx) => { Db.Exec(c, tx, "UPDATE device SET merged_into=NULL WHERE id=$d", ("$d", deviceId)); });

    public Task SetServiceRequiredAsync(string deviceId, string protocol, int port, bool required) =>
        _db.WriteAsync((c, tx) =>
        {
            var root = DeviceRegistry.ResolveRoot(c, tx, deviceId);
            Db.Exec(c, tx, "INSERT OR REPLACE INTO device_service_flag(device_id, protocol, port, required, updated_at) VALUES ($d,$p,$port,$r,$t)",
                ("$d", root), ("$p", protocol), ("$port", port), ("$r", required ? 1 : 0), ("$t", Clock.NowIso()));
        });

    public bool DeviceExists(string id)
    {
        using var c = _db.Open();
        return Db.Scalar<string>(c, null, "SELECT id FROM device WHERE id=$d", ("$d", id)) is not null;
    }

    // ---------- Deletion and retention ----------

    public Task<bool> DeleteScanAsync(string scanId) =>
        _db.WriteAsync((c, tx) => Db.Exec(c, tx, "DELETE FROM scan WHERE id=$id AND state NOT IN ('queued','running','cancelling')", ("$id", scanId)) > 0);

    public Task<int> ApplyRetentionAsync(int days) =>
        _db.WriteAsync((c, tx) => Db.Exec(c, tx, "DELETE FROM scan WHERE started_at < $cut AND state NOT IN ('queued','running','cancelling')",
            ("$cut", Clock.Iso(Clock.Now.AddDays(-days)))));

    public Task DeleteAllAsync() =>
        _db.WriteAsync((c, tx) =>
        {
            foreach (var t in new[] { "badge_award", "score_snapshot", "finding", "port_observation", "scan_host", "scan", "device_service_flag",
                                      "device_label_history", "device_identity", "device", "network_scope", "settings" })
                Db.Exec(c, tx, $"DELETE FROM {t}");
        });

    // ---------- Comparison (FR22) ----------

    public object? Compare(string scanId, string otherId)
    {
        var a = GetSummary(otherId);
        var b = GetSummary(scanId);
        if (a is null || b is null) return null;
        using var c = _db.Open();
        string Snap(string id, string col) => Db.Scalar<string>(c, null, $"SELECT {col} FROM scan WHERE id=$id", ("$id", id)) ?? "";
        static string Prop(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v.ToString() : "";
        var pa = JsonDocument.Parse(Snap(a.Id, "profile_snapshot")).RootElement;
        var pb = JsonDocument.Parse(Snap(b.Id, "profile_snapshot")).RootElement;
        var ta = Prop(JsonDocument.Parse(Snap(a.Id, "target_snapshot")).RootElement, "targets");
        var tb = Prop(JsonDocument.Parse(Snap(b.Id, "target_snapshot")).RootElement, "targets");

        // Standard and advanced snapshot schemas carry different fields; missing fields are not errors but a "different scope".
        var mismatches = new List<string>();
        if (a.NetworkScopeId != b.NetworkScopeId) mismatches.Add("network");
        if (ta != tb) mismatches.Add("targets");
        if (a.ProfileId != b.ProfileId) mismatches.Add("profile");
        if (Prop(pa, "ports") != Prop(pb, "ports") || Prop(pa, "tcp_ports") != Prop(pb, "tcp_ports") || Prop(pa, "udp_ports") != Prop(pb, "udp_ports")) mismatches.Add("ports");
        if (Prop(pa, "method") != Prop(pb, "method") || Prop(pa, "technique") != Prop(pb, "technique") || a.EngineVersion != b.EngineVersion) mismatches.Add("method");
        if (a.RulesetVersion != b.RulesetVersion) mismatches.Add("ruleset");

        var hostsA = GetHosts(a.Id, allObservations: true);
        var hostsB = GetHosts(b.Id, allObservations: true);
        string Key(HostDto h) => h.DeviceId is null ? "ip:" + h.Ip : DeviceRegistry.ResolveRoot(c, null, h.DeviceId);
        var mapA = hostsA.GroupBy(Key).ToDictionary(g => g.Key, g => g.First());
        var mapB = hostsB.GroupBy(Key).ToDictionary(g => g.Key, g => g.First());

        var devices = new List<object>();
        foreach (var key in mapA.Keys.Union(mapB.Keys))
        {
            mapA.TryGetValue(key, out var ha);
            mapB.TryGetValue(key, out var hb);
            var sa = ha?.Open.ToDictionary(o => o.Port, o => o.State) ?? new();
            var sb = hb?.Open.ToDictionary(o => o.Port, o => o.State) ?? new();
            var opened = sb.Where(kv => kv.Value == PortState.Open && (!sa.TryGetValue(kv.Key, out var s) || s != PortState.Open)).Select(kv => kv.Key).Order().ToList();
            var closed = sa.Where(kv => kv.Value == PortState.Open && sb.TryGetValue(kv.Key, out var s) && s == PortState.Closed).Select(kv => kv.Key).Order().ToList();
            var silent = sa.Where(kv => kv.Value == PortState.Open && sb.TryGetValue(kv.Key, out var s) && s is not (PortState.Open or PortState.Closed or PortState.NotTested)).Select(kv => kv.Key).Order().ToList();
            var notMeasured = sa.Where(kv => kv.Value == PortState.Open && (!sb.TryGetValue(kv.Key, out var s) || s == PortState.NotTested)).Select(kv => kv.Key).Order().ToList();
            var status = ha is null ? "new_device" : hb is null ? "not_observed" : opened.Count + closed.Count + silent.Count + notMeasured.Count == 0 ? "unchanged" : "changed";
            devices.Add(new
            {
                device_id = key.StartsWith("ip:", StringComparison.Ordinal) ? null : key,
                label = hb?.Label ?? ha?.Label,
                ip_before = ha?.Ip,
                ip_after = hb?.Ip,
                vendor = hb?.Vendor ?? ha?.Vendor,
                status,
                score_before = ha?.Score,
                score_after = hb?.Score,
                newly_opened = opened,
                closed_with_evidence = closed,
                no_longer_responding = silent,
                not_measured = notMeasured,
            });
        }

        return new
        {
            scan_id = b.Id,
            previous_scan_id = a.Id,
            compatible = mismatches.Count == 0,
            mismatches,
            score_before = a.NetworkScore,
            score_after = b.NetworkScore,
            coverage_before = a.Coverage,
            coverage_after = b.Coverage,
            devices,
        };
    }

    /// <summary>The previous completed scan with the same network, targets, port list and ruleset version.</summary>
    public string? PreviousComparable(string scanId)
    {
        var s = GetSummary(scanId);
        if (s is null) return null;
        using var c = _db.Open();
        return Db.Scalar<string>(c, null, """
            SELECT p.id FROM scan p JOIN scan cur ON cur.id=$id
            WHERE p.network_scope_id=cur.network_scope_id AND p.started_at < cur.started_at AND p.state='completed'
              AND p.profile_snapshot=cur.profile_snapshot AND p.target_snapshot=cur.target_snapshot AND p.ruleset_version=cur.ruleset_version
            ORDER BY p.started_at DESC LIMIT 1
            """, ("$id", scanId))
            ?? Db.Scalar<string>(c, null, """
            SELECT p.id FROM scan p JOIN scan cur ON cur.id=$id
            WHERE p.network_scope_id=cur.network_scope_id AND p.started_at < cur.started_at AND p.state='completed'
            ORDER BY p.started_at DESC LIMIT 1
            """, ("$id", scanId));
    }
}
