namespace Lanora.Net;

public sealed record TargetPlan(IReadOnlyList<uint> Targets, IReadOnlyList<string> Excluded, uint LocalIp, uint? Gateway);

public sealed class TargetValidationException(int status, string code, object? details = null)
    : Infrastructure.ApiException(status, code, details);

/// <summary>
/// FR02: Targets must be inside the selected, directly connected RFC1918 network; at most 256 addresses; deduplicated;
/// network, broadcast, multicast and loopback addresses are removed. The API and the engine use the same validation.
/// </summary>
public static class TargetValidator
{
    public const int MaxAddresses = 256;

    public static TargetPlan Validate(AdapterInfo adapter, IReadOnlyList<string>? targets)
    {
        if (!adapter.Selectable) throw new TargetValidationException(403, "NETWORK_NOT_SELECTABLE");
        var net = adapter.Network;
        var local = adapter.IpValue;
        uint? gateway = adapter.Gateway is null ? null : Ipv4.Parse(adapter.Gateway);

        var items = (targets ?? Array.Empty<string>()).Select(t => (t ?? string.Empty).Trim()).Where(t => t.Length > 0).ToList();
        if (items.Count == 0) throw new TargetValidationException(400, "TARGET_EMPTY");
        if (items.Count > 1024) throw new TargetValidationException(400, "TARGET_LIMIT", new { max = MaxAddresses });

        var set = new HashSet<uint>();
        foreach (var item in items)
        {
            foreach (var ip in Expand(item))
            {
                set.Add(ip);
                if (set.Count > MaxAddresses) throw new TargetValidationException(400, "TARGET_LIMIT", new { max = MaxAddresses });
            }
        }

        var excluded = new List<string>();
        var result = new List<uint>();
        foreach (var ip in set.OrderBy(x => x))
        {
            if (Ipv4.IsLoopback(ip) || Ipv4.IsMulticast(ip) || Ipv4.IsReservedOrUnspecified(ip))
            {
                excluded.Add(Ipv4.Format(ip));
                continue;
            }
            if (!Ipv4.IsPrivate(ip)) throw new TargetValidationException(403, "TARGET_NOT_PRIVATE", new { target = Ipv4.Format(ip) });
            if (!net.Contains(ip)) throw new TargetValidationException(403, "TARGET_OUT_OF_SCOPE", new { target = Ipv4.Format(ip), network = net.ToString() });
            if (net.Prefix <= 30 && (ip == net.Network || ip == net.Broadcast))
            {
                excluded.Add(Ipv4.Format(ip));
                continue;
            }
            result.Add(ip);
        }

        if (result.Count == 0) throw new TargetValidationException(400, "TARGET_EMPTY");
        return new TargetPlan(result, excluded, local, gateway);
    }

    /// <summary>"a.b.c.d", "a.b.c.d/n" or "a.b.c.d-e" / "a.b.c.d-a.b.c.e". Hostnames are rejected.</summary>
    private static IEnumerable<uint> Expand(string item)
    {
        if (item.Contains('/'))
        {
            if (!Cidr.TryParse(item, out var c)) throw new TargetValidationException(400, "TARGET_INVALID", new { target = item });
            if (c.AddressCount > MaxAddresses) throw new TargetValidationException(400, "TARGET_LIMIT", new { max = MaxAddresses, target = item });
            for (long ip = c.Network; ip <= c.Broadcast; ip++) yield return (uint)ip;
            yield break;
        }

        var dash = item.IndexOf('-');
        if (dash > 0)
        {
            var left = item[..dash].Trim();
            var right = item[(dash + 1)..].Trim();
            if (!Ipv4.TryParse(left, out var start)) throw new TargetValidationException(400, "TARGET_INVALID", new { target = item });
            uint end;
            if (Ipv4.TryParse(right, out var full)) end = full;
            else if (byte.TryParse(right, out var last)) end = (start & 0xFFFFFF00) | last;
            else throw new TargetValidationException(400, "TARGET_INVALID", new { target = item });
            if (end < start) throw new TargetValidationException(400, "TARGET_INVALID", new { target = item });
            if ((long)end - start + 1 > MaxAddresses) throw new TargetValidationException(400, "TARGET_LIMIT", new { max = MaxAddresses, target = item });
            for (long ip = start; ip <= end; ip++) yield return (uint)ip;
            yield break;
        }

        if (!Ipv4.TryParse(item, out var single))
            throw new TargetValidationException(400, "TARGET_INVALID", new { target = item, hint = "hostname_not_allowed" });
        yield return single;
    }
}
