using Lanora.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Lanora.Data;

/// <summary>
/// Local SQLite: WAL mode, foreign keys on every connection, single-writer queue. A consistent backup is taken before migration;
/// no scan starts after a failed upgrade. Unfinished jobs are marked interrupted at startup.
/// </summary>
public sealed class Database : IDisposable
{
    public const int SchemaVersion = 2;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly string _connectionString;
    private readonly AppPaths _paths;

    public Database(AppPaths paths)
    {
        _paths = paths;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = paths.Database,
            Mode = SqliteOpenMode.ReadWriteCreate,
            ForeignKeys = true,
            Pooling = true,
            DefaultTimeout = 30,
        }.ToString();
    }

    public bool MigrationFailed { get; private set; }

    public SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString);
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;";
        cmd.ExecuteNonQuery();
        return c;
    }

    public async Task<T> WriteAsync<T>(Func<SqliteConnection, SqliteTransaction, T> work, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var c = Open();
            using var tx = c.BeginTransaction();
            var result = work(c, tx);
            tx.Commit();
            return result;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public Task WriteAsync(Action<SqliteConnection, SqliteTransaction> work, CancellationToken ct = default) =>
        WriteAsync<bool>((c, t) => { work(c, t); return true; }, ct);

    public void Initialize()
    {
        using (var c = Open())
        {
            Db.Exec(c, null, "PRAGMA journal_mode=WAL;");
            Db.Exec(c, null, "CREATE TABLE IF NOT EXISTS schema_info(version INTEGER NOT NULL);");
            var version = Db.Scalar<long?>(c, null, "SELECT MAX(version) FROM schema_info") ?? 0;
            if (version < SchemaVersion)
            {
                if (version > 0) Backup("pre-migration");
                try
                {
                    using var tx = c.BeginTransaction();
                    Migrate(c, tx, (int)version);
                    tx.Commit();
                }
                catch (Exception ex)
                {
                    MigrationFailed = true;
                    AppLog.Error("migration", ex);
                    return;
                }
            }
            else if (version > SchemaVersion)
            {
                MigrationFailed = true;
                AppLog.Error("migration", $"database schema {version} is newer than application schema {SchemaVersion}");
                return;
            }

            var n = Db.Exec(c, null, "UPDATE scan SET state='interrupted', reason_code='APP_RESTARTED', ended_at=COALESCE(ended_at, $now) WHERE state IN ('queued','running','cancelling')",
                ("$now", Clock.NowIso()));
            if (n > 0) AppLog.Warn("startup", $"{n} unfinished scan(s) marked interrupted");
        }
    }

    private static void Migrate(SqliteConnection c, SqliteTransaction tx, int from)
    {
        if (from < 1)
        {
            Db.Exec(c, tx, Schema.V1);
        }
        if (from < 2)
        {
            // Advanced scan enrichments and fields.
            Db.Exec(c, tx, """
                ALTER TABLE scan_host ADD COLUMN hostname TEXT;
                ALTER TABLE scan_host ADD COLUMN hostname_type TEXT;
                ALTER TABLE scan_host ADD COLUMN ipv6 TEXT;
                ALTER TABLE scan_host ADD COLUMN distance INTEGER;
                ALTER TABLE scan_host ADD COLUMN scripts_json TEXT;
                ALTER TABLE scan_host ADD COLUMN trace_json TEXT;
                ALTER TABLE port_observation ADD COLUMN scripts_json TEXT;
                """);
        }
        Db.Exec(c, tx, "DELETE FROM schema_info; INSERT INTO schema_info(version) VALUES ($v);", ("$v", SchemaVersion));
    }

    /// <summary>FR27: The live WAL database file is never copied; the SQLite backup API is used.</summary>
    public string Backup(string label)
    {
        var name = $"lanora-{label}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.db";
        var path = Path.Combine(_paths.Backups, name);
        using (var src = Open())
        using (var dst = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
        {
            dst.Open();
            src.BackupDatabase(dst);
        }
        // The 5 newest managed backups are kept.
        foreach (var old in new DirectoryInfo(_paths.Backups).GetFiles("lanora-*.db").OrderByDescending(f => f.CreationTimeUtc).Skip(5))
        {
            try { old.Delete(); } catch { }
        }
        return path;
    }

    public void DeleteManagedBackups()
    {
        foreach (var f in Directory.GetFiles(_paths.Backups, "lanora-*.db"))
        {
            try { File.Delete(f); } catch { }
        }
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        _writeLock.Dispose();
    }
}

internal static class Schema
{
    public const string V1 = """
        CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);

        CREATE TABLE network_scope(
            id TEXT PRIMARY KEY,
            adapter_guid TEXT NOT NULL,
            network_cidr TEXT NOT NULL,
            gateway_identity TEXT,
            user_name TEXT,
            created_at TEXT NOT NULL);
        CREATE UNIQUE INDEX ux_scope ON network_scope(adapter_guid, network_cidr, IFNULL(gateway_identity,''));

        CREATE TABLE device(
            id TEXT PRIMARY KEY,
            network_scope_id TEXT NOT NULL REFERENCES network_scope(id) ON DELETE CASCADE,
            custom_name TEXT,
            user_type TEXT,
            notes TEXT,
            merged_into TEXT REFERENCES device(id) ON DELETE SET NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL);
        CREATE INDEX ix_device_scope ON device(network_scope_id);

        CREATE TABLE device_identity(
            id INTEGER PRIMARY KEY,
            device_id TEXT NOT NULL REFERENCES device(id) ON DELETE CASCADE,
            network_scope_id TEXT NOT NULL REFERENCES network_scope(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            confidence TEXT NOT NULL,
            valid_from TEXT NOT NULL,
            valid_to TEXT,
            source TEXT NOT NULL);
        CREATE INDEX ix_identity ON device_identity(network_scope_id, kind, value);

        CREATE TABLE device_label_history(
            id INTEGER PRIMARY KEY,
            device_id TEXT NOT NULL REFERENCES device(id) ON DELETE CASCADE,
            old_name TEXT, new_name TEXT, old_type TEXT, new_type TEXT,
            changed_at TEXT NOT NULL);

        CREATE TABLE device_service_flag(
            device_id TEXT NOT NULL REFERENCES device(id) ON DELETE CASCADE,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            required INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(device_id, protocol, port));

        CREATE TABLE scan(
            id TEXT PRIMARY KEY,
            network_scope_id TEXT NOT NULL REFERENCES network_scope(id) ON DELETE CASCADE,
            state TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            profile_id TEXT NOT NULL,
            profile_snapshot TEXT NOT NULL,
            target_snapshot TEXT NOT NULL,
            interface_snapshot TEXT NOT NULL,
            rate_snapshot TEXT NOT NULL,
            engine_version TEXT NOT NULL,
            ruleset_version TEXT NOT NULL,
            reason_code TEXT,
            addresses_probed INTEGER NOT NULL DEFAULT 0,
            hosts_responded INTEGER NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX ix_scan_started ON scan(started_at);
        CREATE INDEX ix_scan_scope ON scan(network_scope_id, started_at);

        CREATE TABLE scan_host(
            id INTEGER PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
            device_id TEXT REFERENCES device(id) ON DELETE SET NULL,
            ip TEXT NOT NULL,
            mac_snapshot TEXT,
            mac_kind TEXT,
            vendor_snapshot TEXT,
            label_snapshot TEXT,
            type_snapshot TEXT,
            type_guess TEXT,
            is_local INTEGER NOT NULL,
            is_gateway INTEGER NOT NULL,
            identity_status TEXT NOT NULL,
            discovery_evidence TEXT NOT NULL,
            icmp_ttl INTEGER,
            os_candidate TEXT,
            os_source TEXT,
            os_confidence TEXT,
            planned_pairs INTEGER NOT NULL,
            definite_pairs INTEGER NOT NULL,
            score INTEGER,
            raw_score INTEGER NOT NULL,
            penalty INTEGER NOT NULL);
        CREATE INDEX ix_scan_host_scan ON scan_host(scan_id);
        CREATE INDEX ix_scan_host_device ON scan_host(device_id);

        CREATE TABLE port_observation(
            id INTEGER PRIMARY KEY,
            scan_host_id INTEGER NOT NULL REFERENCES scan_host(id) ON DELETE CASCADE,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            reason_code TEXT,
            method TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            attempts INTEGER NOT NULL,
            service_name TEXT,
            service_method TEXT,
            service_product TEXT,
            service_version TEXT,
            evidence_summary TEXT,
            raw_state TEXT,
            UNIQUE(scan_host_id, protocol, port));

        CREATE TABLE finding(
            id INTEGER PRIMARY KEY,
            scan_host_id INTEGER NOT NULL REFERENCES scan_host(id) ON DELETE CASCADE,
            observation_id INTEGER REFERENCES port_observation(id) ON DELETE CASCADE,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            penalty INTEGER NOT NULL,
            recommendation_key TEXT NOT NULL,
            evidence_reference TEXT,
            uncertain_count INTEGER);
        CREATE INDEX ix_finding_host ON finding(scan_host_id);

        CREATE TABLE score_snapshot(
            scan_id TEXT PRIMARY KEY REFERENCES scan(id) ON DELETE CASCADE,
            scope TEXT NOT NULL,
            host_scores TEXT NOT NULL,
            network_score INTEGER,
            network_state TEXT NOT NULL,
            coverage REAL NOT NULL,
            planned_pairs INTEGER NOT NULL,
            definite_pairs INTEGER NOT NULL,
            provisional INTEGER NOT NULL,
            calculated_at TEXT NOT NULL,
            ruleset_version TEXT NOT NULL);

        CREATE TABLE badge_award(
            id INTEGER PRIMARY KEY,
            badge_key TEXT NOT NULL,
            network_scope_id TEXT REFERENCES network_scope(id) ON DELETE CASCADE,
            device_id TEXT,
            scan_id TEXT,
            awarded_at TEXT NOT NULL,
            active INTEGER NOT NULL,
            deactivated_at TEXT);
        """;
}
