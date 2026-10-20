using Lanora.Infrastructure;
using Lanora.Net;
using Lanora.Scanning;
using Microsoft.Data.Sqlite;

namespace Lanora.Data;

public sealed record DeviceResolution(string? DeviceId, string IdentityStatus, string? MacKind, string? Label, string? UserType);

/// <summary>
/// FR12: The persistent device_id is a UUID independent of the IP. Matching relies on MAC and past evidence within the network scope.
/// When the same MAC gets a new IP the label is kept; when the same IP shows up with a different MAC the label is not carried over.
/// A random (locally administered) MAC matches only together with the same IP; otherwise it is marked uncertain.
/// </summary>
public static class DeviceRegistry
{
    public static DeviceResolution Resolve(SqliteConnection c, SqliteTransaction tx, string scopeId, HostResult h, string now)
    {
        var mac = h.Mac;
        if (mac is null)
        {
            // Without a MAC the IP alone is not an identity: new record, relation uncertain.
            var id = CreateDevice(c, tx, scopeId, now);
            return new DeviceResolution(id, "ambiguous", null, null, null);
        }

        var local = MacAddress.IsLocallyAdministered(mac);
        var macKind = local ? "local_admin" : "universal";
        var existing = Db.Scalar<string>(c, tx,
            "SELECT device_id FROM device_identity WHERE network_scope_id=$s AND kind='mac' AND value=$v AND valid_to IS NULL ORDER BY id DESC LIMIT 1",
            ("$s", scopeId), ("$v", mac));

        if (existing is not null)
        {
            var root = ResolveRoot(c, tx, existing);
            var matched = !local;
            if (local)
            {
                var lastIp = Db.Scalar<string>(c, tx,
                    "SELECT ip FROM scan_host WHERE device_id IN (SELECT id FROM device WHERE id=$d OR merged_into=$d) ORDER BY id DESC LIMIT 1", ("$d", root));
                matched = lastIp == h.IpText;
            }
            if (matched)
            {
                Db.Exec(c, tx, "UPDATE device SET last_seen=$n WHERE id=$d", ("$n", now), ("$d", root));
                var (label, type) = Labels(c, tx, root);
                return new DeviceResolution(root, "matched", macKind, label, type);
            }
            var fresh = CreateDevice(c, tx, scopeId, now);
            AddIdentity(c, tx, fresh, scopeId, "mac", mac, "low", now, "arp_neighbor_table");
            return new DeviceResolution(fresh, "ambiguous", macKind, null, null);
        }

        var created = CreateDevice(c, tx, scopeId, now);
        AddIdentity(c, tx, created, scopeId, "mac", mac, local ? "low" : "high", now, h.MacSource ?? "arp_neighbor_table");
        return new DeviceResolution(created, "new", macKind, null, null);
    }

    public static string ResolveRoot(SqliteConnection c, SqliteTransaction? tx, string deviceId)
    {
        var current = deviceId;
        for (var i = 0; i < 16; i++)
        {
            var parent = Db.Scalar<string>(c, tx, "SELECT merged_into FROM device WHERE id=$d", ("$d", current));
            if (parent is null) return current;
            current = parent;
        }
        return current;
    }

    private static (string?, string?) Labels(SqliteConnection c, SqliteTransaction tx, string id)
    {
        var r = Db.Query(c, tx, "SELECT custom_name, user_type FROM device WHERE id=$d", x => (x.Str("custom_name"), x.Str("user_type")), ("$d", id));
        return r.Count == 0 ? (null, null) : r[0];
    }

    private static string CreateDevice(SqliteConnection c, SqliteTransaction tx, string scopeId, string now)
    {
        var id = Guid.NewGuid().ToString();
        Db.Exec(c, tx, "INSERT INTO device(id, network_scope_id, first_seen, last_seen) VALUES ($i,$s,$n,$n)", ("$i", id), ("$s", scopeId), ("$n", now));
        return id;
    }

    private static void AddIdentity(SqliteConnection c, SqliteTransaction tx, string deviceId, string scopeId, string kind, string value, string confidence, string now, string source) =>
        Db.Exec(c, tx,
            "INSERT INTO device_identity(device_id, network_scope_id, kind, value, confidence, valid_from, source) VALUES ($d,$s,$k,$v,$c,$n,$src)",
            ("$d", deviceId), ("$s", scopeId), ("$k", kind), ("$v", value), ("$c", confidence), ("$n", now), ("$src", source));

    public static string EnsureScope(SqliteConnection c, SqliteTransaction tx, AdapterInfo a)
    {
        var gw = a.Gateway ?? "";
        var id = Db.Scalar<string>(c, tx,
            "SELECT id FROM network_scope WHERE adapter_guid=$g AND network_cidr=$n AND IFNULL(gateway_identity,'')=$gw",
            ("$g", a.AdapterGuid), ("$n", a.NetworkCidr), ("$gw", gw));
        if (id is not null) return id;
        id = Guid.NewGuid().ToString();
        Db.Exec(c, tx, "INSERT INTO network_scope(id, adapter_guid, network_cidr, gateway_identity, user_name, created_at) VALUES ($i,$g,$n,$gw,NULL,$t)",
            ("$i", id), ("$g", a.AdapterGuid), ("$n", a.NetworkCidr), ("$gw", a.Gateway), ("$t", Clock.NowIso()));
        return id;
    }
}
