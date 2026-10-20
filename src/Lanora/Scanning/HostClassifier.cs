namespace Lanora.Scanning;

/// <summary>
/// Low-confidence estimates of device type and operating system. FR10: stored with the estimate source and confidence level;
/// active TCP/IP fingerprinting belongs to the V1.1 engine. Returns null (Unknown) on insufficient evidence.
/// </summary>
public static class HostClassifier
{
    /// <param name="includeOs">When false, no operating system estimate is made and any existing estimate is cleared.</param>
    public static void Classify(HostResult h, bool includeOs = true)
    {
        var open = h.Ports.Values.Where(p => p.State == PortState.Open).Select(p => p.Port).ToHashSet();
        var vendor = (h.Vendor ?? string.Empty).ToLowerInvariant();
        h.TypeGuess = GuessType(h, open, vendor);
        if (!includeOs)
        {
            (h.OsCandidate, h.OsSource, h.OsConfidence) = (null, null, null);
            return;
        }
        // Do not overwrite the OS if a stronger source already filled it.
        if (h.OsCandidate is null)
            (h.OsCandidate, h.OsSource, h.OsConfidence) = GuessOs(h, open);
    }

    private static string? GuessType(HostResult h, HashSet<int> open, string vendor)
    {
        if (h.IsLocal) return "computer";
        if (h.IsGateway) return "router";
        if (open.Overlaps(new[] { 9100, 515, 631 })) return "printer";
        if (open.Contains(62078)) return "phone";
        if (open.Contains(1400) || vendor.Contains("sonos")) return "speaker";
        if (open.Overlaps(new[] { 8008, 8009 })) return "media";
        if (open.Contains(554) && !open.Contains(3389)) return "camera";
        if (vendor.Contains("synology") || vendor.Contains("qnap") || vendor.Contains("western digital") || open.Contains(548) || open.Contains(2049)) return "storage";
        if (open.Overlaps(new[] { 3389, 445, 135, 139, 5985 })) return "computer";
        if (open.Overlaps(new[] { 8001, 8002, 7000, 7100 }) && (vendor.Contains("samsung") || vendor.Contains("lg ") || vendor.Contains("sony") || vendor.Contains("tcl") || vendor.Contains("hisense"))) return "tv";
        if (vendor.Contains("espressif") || vendor.Contains("tuya") || vendor.Contains("shelly") || open.Contains(1883) || open.Contains(8883)) return "iot";
        return null;
    }

    private static (string?, string?, string?) GuessOs(HostResult h, HashSet<int> open)
    {
        if (h.IsLocal) return ("Windows", "local_system", "high");

        foreach (var p in h.Ports.Values)
        {
            var summary = p.Service?.Summary ?? string.Empty;
            if (p.Port is 22 or 2222 && summary.StartsWith("SSH-", StringComparison.Ordinal))
            {
                if (summary.Contains("Ubuntu", StringComparison.OrdinalIgnoreCase)) return ("Linux (Ubuntu)", "ssh_banner", "medium");
                if (summary.Contains("Debian", StringComparison.OrdinalIgnoreCase)) return ("Linux (Debian)", "ssh_banner", "medium");
                if (summary.Contains("Raspbian", StringComparison.OrdinalIgnoreCase)) return ("Linux (Raspberry Pi OS)", "ssh_banner", "medium");
            }
        }

        var ttl = h.IcmpTtl;
        var windowsPorts = open.Overlaps(new[] { 135, 139, 445, 3389, 5985 });
        if (ttl is > 64 and <= 128 && windowsPorts) return ("Windows", "icmp_ttl+port_pattern", "medium");
        if (windowsPorts && open.Contains(135)) return ("Windows", "port_pattern", "low");
        if (ttl is > 64 and <= 128) return ("Windows", "icmp_ttl", "low");
        if (ttl is > 0 and <= 64 && open.Contains(62078)) return ("iOS / iPadOS", "icmp_ttl+port_pattern", "low");
        if (ttl is > 0 and <= 64) return ("Linux / Unix", "icmp_ttl", "low");
        if (ttl is > 128) return ("Embedded / network OS", "icmp_ttl", "low");
        return (null, null, null);
    }
}
