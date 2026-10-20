using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Lanora.Net;

public sealed record AdapterInfo
{
    public required string Id { get; init; }
    public required string AdapterGuid { get; init; }
    public required string Name { get; init; }
    public required string Description { get; init; }
    /// <summary>ethernet | wifi | vpn | virtual | other</summary>
    public required string Kind { get; init; }
    public required string Ip { get; init; }
    public required int PrefixLength { get; init; }
    public required string NetworkCidr { get; init; }
    public string? Gateway { get; init; }
    public string? Mac { get; init; }
    public uint InterfaceIndex { get; init; }
    public bool IsDefaultRoute { get; init; }
    public bool IsPrivate { get; init; }
    public long AddressCount { get; init; }
    public bool Selectable { get; init; }
    public string? NotSelectableReason { get; init; }
    /// <summary>Selectable ranges of at most 256 addresses. Larger networks are never silently treated as /24.</summary>
    public required IReadOnlyList<string> Ranges { get; init; }
    public string? SuggestedRange { get; init; }
    public bool RangeSelectionRequired { get; init; }

    internal Cidr Network => Cidr.TryParse(NetworkCidr, out var c) ? c : default;
    internal uint IpValue => Ipv4.Parse(Ip);
}

/// <summary>FR01: Active adapters, real CIDR, gateway and selectable ranges.</summary>
public sealed partial class NetworkInfoService
{
    [GeneratedRegex(@"vpn|wireguard|openvpn|tap-|tun\b|tailscale|zerotier|nordlynx|anyconnect|fortinet|forticlient|globalprotect|pangp|juniper|sonicwall|wintun|proton", RegexOptions.IgnoreCase)]
    private static partial Regex VpnPattern();

    [GeneratedRegex(@"virtual|hyper-v|vethernet|vmware|virtualbox|vbox|wsl|docker|loopback|bluetooth|parallels|qemu|kvm", RegexOptions.IgnoreCase)]
    private static partial Regex VirtualPattern();

    public IReadOnlyList<AdapterInfo> GetAdapters()
    {
        var defaultIf = SafeDefaultRoute();
        var list = new List<AdapterInfo>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            IPInterfaceProperties props;
            uint index = 0;
            try
            {
                props = ni.GetIPProperties();
                index = (uint)(props.GetIPv4Properties()?.Index ?? 0);
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            var gateway = props.GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(System.Net.IPAddress.Any));
            var kind = Classify(ni);
            string? mac = null;
            try { mac = MacAddress.Format(ni.GetPhysicalAddress().GetAddressBytes()); } catch { }

            foreach (var ua in props.UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                var ip = Ipv4.FromAddress(ua.Address);
                if (Ipv4.IsLoopback(ip)) continue;
                var prefix = ua.PrefixLength;
                var net = Cidr.FromAddress(ip, prefix);
                var isPrivate = Ipv4.IsPrivate(ip) && Ipv4.IsPrivate(net.Network) && Ipv4.IsPrivate(net.Broadcast);
                string? reason = null;
                if (!isPrivate) reason = "NETWORK_NOT_PRIVATE";
                else if (prefix > 30) reason = "NETWORK_TOO_SMALL";
                else if ((ip & 0xFFFF0000) == 0xA9FE0000) reason = "LINK_LOCAL";

                var (ranges, suggested, required) = BuildRanges(net, ip);
                uint? gw = gateway is null ? null : Ipv4.FromAddress(gateway);
                list.Add(new AdapterInfo
                {
                    Id = $"{ni.Id}/{Ipv4.Format(ip)}",
                    AdapterGuid = ni.Id,
                    Name = ni.Name,
                    Description = ni.Description,
                    Kind = kind,
                    Ip = Ipv4.Format(ip),
                    PrefixLength = prefix,
                    NetworkCidr = net.ToString(),
                    Gateway = gw is { } g && net.Contains(g) ? Ipv4.Format(g) : null,
                    Mac = mac,
                    InterfaceIndex = index,
                    IsDefaultRoute = defaultIf is { } d && d == index,
                    IsPrivate = isPrivate,
                    AddressCount = net.AddressCount,
                    Selectable = reason is null,
                    NotSelectableReason = reason,
                    Ranges = reason is null ? ranges : Array.Empty<string>(),
                    SuggestedRange = reason is null ? suggested : null,
                    RangeSelectionRequired = required,
                });
            }
        }

        // Suggestion order: default route > physical > other.
        return list
            .OrderByDescending(a => a.Selectable)
            .ThenByDescending(a => a.IsDefaultRoute)
            .ThenBy(a => a.Kind switch { "ethernet" => 0, "wifi" => 1, "other" => 2, "vpn" => 3, _ => 4 })
            .ThenBy(a => a.Name, StringComparer.CurrentCulture)
            .ToList();
    }

    public AdapterInfo? Find(string id) => GetAdapters().FirstOrDefault(a => a.Id == id);

    internal static (IReadOnlyList<string> Ranges, string Suggested, bool Required) BuildRanges(Cidr net, uint ip)
    {
        if (net.Prefix >= 24) return (new[] { net.ToString() }, net.ToString(), false);
        var own = Cidr.FromAddress(ip, 24);
        var ranges = new List<string> { own.ToString() };
        // Suggest a few neighboring /24 blocks; the user can also type another range inside the network.
        for (var step = 1; step <= 3 && ranges.Count < 7; step++)
        {
            foreach (var delta in new[] { -step, step })
            {
                var candidate = (long)own.Network + delta * 256L;
                if (candidate < net.Network || candidate > net.Broadcast) continue;
                ranges.Add(new Cidr((uint)candidate, 24).ToString());
            }
        }
        return (ranges, own.ToString(), true);
    }

    private static string Classify(NetworkInterface ni)
    {
        var text = ni.Name + " " + ni.Description;
        if (ni.NetworkInterfaceType is NetworkInterfaceType.Ppp or NetworkInterfaceType.Tunnel || VpnPattern().IsMatch(text)) return "vpn";
        if (VirtualPattern().IsMatch(text)) return "virtual";
        return ni.NetworkInterfaceType switch
        {
            NetworkInterfaceType.Wireless80211 => "wifi",
            NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.FastEthernetT
                or NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.Ethernet3Megabit => "ethernet",
            _ => "other",
        };
    }

    private static uint? SafeDefaultRoute()
    {
        try { return NativeMethods.GetDefaultRouteInterface(); }
        catch { return null; }
    }
}
