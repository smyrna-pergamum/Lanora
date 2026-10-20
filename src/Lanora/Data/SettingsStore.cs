using Lanora.Infrastructure;
using Lanora.Risk;

namespace Lanora.Data;

public sealed record AppSettings(string Lang, string Theme, string Retention, bool Tips, string DefaultProfile);

public sealed class SettingsStore
{
    public static readonly string[] Languages = { "en", "tr", "de" };
    public static readonly string[] Retentions = { "30", "90", "180", "365", "off" };
    private readonly Database _db;

    public SettingsStore(Database db) => _db = db;

    public AppSettings Get()
    {
        using var c = _db.Open();
        var map = Db.Query(c, null, "SELECT key, value FROM settings", r => (r.Str("key")!, r.Str("value")!)).ToDictionary(x => x.Item1, x => x.Item2);
        string V(string k, string d) => map.TryGetValue(k, out var v) ? v : d;
        return new AppSettings(V("lang", "en"), V("theme", "light"), V("retention", "180"), V("tips", "1") == "1", V("default_profile", "quick"));
    }

    public Task SetAsync(IReadOnlyDictionary<string, string> values) =>
        _db.WriteAsync((c, tx) =>
        {
            foreach (var (k, v) in values)
                Db.Exec(c, tx, "INSERT OR REPLACE INTO settings(key, value) VALUES ($k,$v)", ("$k", k), ("$v", v));
        });
}

/// <summary>
/// FR20: First Scan Completed; Network Guardian (same network and profile, 3 completed scans on different days);
/// No Priority Findings (completed standard scan, ≥90% definite-result coverage). A cancelled scan earns no badge.
/// </summary>
public sealed class BadgeService
{
    public const string FirstScan = "first_scan";
    public const string Guardian = "network_guardian";
    public const string NoPriority = "no_priority_findings";
    private readonly Database _db;

    public BadgeService(Database db) => _db = db;

    public Task EvaluateAsync(string scanId) =>
        _db.WriteAsync((c, tx) =>
        {
            var row = Db.Query(c, tx, """
                SELECT s.state, s.network_scope_id, s.profile_id, ss.coverage,
                    (SELECT COUNT(*) FROM finding f JOIN scan_host h ON h.id=f.scan_host_id WHERE h.scan_id=s.id AND f.severity IN ('high','medium')) AS prio
                FROM scan s LEFT JOIN score_snapshot ss ON ss.scan_id=s.id WHERE s.id=$id
                """, r => new { State = r.Str("state")!, Scope = r.Str("network_scope_id")!, Profile = r.Str("profile_id")!, Coverage = r.Dbl("coverage") ?? 0, Prio = r.Long("prio") ?? 0 },
                ("$id", scanId)).SingleOrDefault();
            if (row is null || row.State != "completed") return;
            var now = Clock.NowIso();

            if (Db.Scalar<long>(c, tx, "SELECT COUNT(*) FROM badge_award WHERE badge_key=$k", ("$k", FirstScan)) == 0)
                Award(c, tx, FirstScan, row.Scope, scanId, now);

            var days = GuardianDays(c, tx, row.Scope, row.Profile);
            if (days >= 3 && Db.Scalar<long>(c, tx, "SELECT COUNT(*) FROM badge_award WHERE badge_key=$k AND network_scope_id=$s", ("$k", Guardian), ("$s", row.Scope)) == 0)
                Award(c, tx, Guardian, row.Scope, scanId, now);

            if (row.Prio > 0)
            {
                Db.Exec(c, tx, "UPDATE badge_award SET active=0, deactivated_at=$t WHERE badge_key=$k AND network_scope_id=$s AND active=1",
                    ("$t", now), ("$k", NoPriority), ("$s", row.Scope));
            }
            else if (row.Profile == "standard" && row.Coverage >= 0.90 &&
                     Db.Scalar<long>(c, tx, "SELECT COUNT(*) FROM badge_award WHERE badge_key=$k AND network_scope_id=$s AND active=1", ("$k", NoPriority), ("$s", row.Scope)) == 0)
            {
                Award(c, tx, NoPriority, row.Scope, scanId, now);
            }
        });

    private static int GuardianDays(Microsoft.Data.Sqlite.SqliteConnection c, Microsoft.Data.Sqlite.SqliteTransaction? tx, string scope, string profile)
    {
        var starts = Db.Query(c, tx, "SELECT started_at FROM scan WHERE network_scope_id=$s AND profile_id=$p AND state='completed'",
            r => Clock.Parse(r.Str("started_at")!).ToLocalTime().Date, ("$s", scope), ("$p", profile));
        return starts.Distinct().Count();
    }

    private static void Award(Microsoft.Data.Sqlite.SqliteConnection c, Microsoft.Data.Sqlite.SqliteTransaction tx, string key, string scope, string scanId, string now) =>
        Db.Exec(c, tx, "INSERT INTO badge_award(badge_key, network_scope_id, scan_id, awarded_at, active) VALUES ($k,$s,$scan,$t,1)",
            ("$k", key), ("$s", scope), ("$scan", scanId), ("$t", now));

    public List<BadgeDto> Get(string? scope)
    {
        using var c = _db.Open();
        var awards = Db.Query(c, null, "SELECT * FROM badge_award WHERE ($s IS NULL OR network_scope_id=$s OR badge_key=$f) ORDER BY awarded_at DESC",
            r => new { Key = r.Str("badge_key")!, Active = r.Bool("active"), At = r.Str("awarded_at"), Off = r.Str("deactivated_at") },
            ("$s", scope), ("$f", FirstScan));
        var guardianProgress = 0;
        if (scope is not null)
        {
            var profiles = Db.Query(c, null, "SELECT DISTINCT profile_id FROM scan WHERE network_scope_id=$s", r => r.Str("profile_id")!, ("$s", scope));
            guardianProgress = profiles.Count == 0 ? 0 : profiles.Max(p => GuardianDays(c, null, scope, p));
        }
        BadgeDto Make(string key, int? progress, int? goal)
        {
            var a = awards.FirstOrDefault(x => x.Key == key && x.Active) ?? awards.FirstOrDefault(x => x.Key == key);
            return new BadgeDto(key, a is not null, a?.Active ?? false, a?.At, a?.Off, progress, goal);
        }
        return new List<BadgeDto>
        {
            Make(FirstScan, null, null),
            Make(Guardian, Math.Min(3, guardianProgress), 3),
            Make(NoPriority, null, null),
        };
    }
}

/// <summary>FR26: Deletes scans past their retention period together with related observations and findings.</summary>
public sealed class RetentionService : IDisposable
{
    private readonly ScanStore _store;
    private readonly SettingsStore _settings;
    private readonly Timer _timer;

    public RetentionService(ScanStore store, SettingsStore settings)
    {
        _store = store;
        _settings = settings;
        _timer = new Timer(_ => _ = RunAsync(), null, TimeSpan.FromSeconds(10), TimeSpan.FromHours(6));
    }

    public async Task RunAsync()
    {
        try
        {
            var r = _settings.Get().Retention;
            if (r == "off" || !int.TryParse(r, out var days)) return;
            var n = await _store.ApplyRetentionAsync(days).ConfigureAwait(false);
            if (n > 0) AppLog.Info("retention", $"{n} scan(s) older than {days} days deleted");
        }
        catch (Exception ex)
        {
            AppLog.Error("retention", ex);
        }
    }

    public void Dispose() => _timer.Dispose();
}
