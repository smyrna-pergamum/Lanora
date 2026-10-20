using Lanora.Infrastructure;

namespace Lanora.Net;

/// <summary>FR09: Offline OUI lookup (IEEE MA-L list, embedded in the application). No external API is used.</summary>
public sealed class OuiDatabase
{
    private readonly Lazy<Dictionary<string, string>> _map = new(Load);

    public string Source => "IEEE MA-L (offline)";

    /// <summary>Vendor name or null. No vendor is claimed for a locally administered MAC.</summary>
    public string? Lookup(string? mac)
    {
        if (string.IsNullOrEmpty(mac) || mac.Length < 8) return null;
        if (MacAddress.IsLocallyAdministered(mac) || MacAddress.IsMulticast(mac)) return null;
        var key = mac.Replace(":", string.Empty, StringComparison.Ordinal)[..6].ToUpperInvariant();
        return _map.Value.TryGetValue(key, out var org) ? org : null;
    }

    private static Dictionary<string, string> Load()
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            foreach (var line in Res.ReadText("res/oui.tsv.gz").Split('\n'))
            {
                if (line.Length < 8 || line[0] == '#') continue;
                var tab = line.IndexOf('\t');
                if (tab != 6) continue;
                map[line[..6]] = line[(tab + 1)..].TrimEnd('\r');
            }
        }
        catch (Exception ex)
        {
            AppLog.Error("oui", ex);
        }
        return map;
    }
}
