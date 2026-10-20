using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace Lanora.Net;

/// <summary>IPv4 helpers. Addresses are stored as uint in host byte order.</summary>
public static partial class Ipv4
{
    [GeneratedRegex(@"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", RegexOptions.CultureInvariant)]
    private static partial Regex DottedQuad();

    /// <summary>Accepts only the four-octet decimal form (forms such as "1" or "0x7f.1" are rejected).</summary>
    public static bool TryParse(string? text, out uint value)
    {
        value = 0;
        if (text is null) return false;
        var m = DottedQuad().Match(text.Trim());
        if (!m.Success) return false;
        for (var i = 1; i <= 4; i++)
        {
            var part = m.Groups[i].Value;
            if (part.Length > 1 && part[0] == '0') return false;
            var n = int.Parse(part, CultureInfo.InvariantCulture);
            if (n > 255) return false;
            value = (value << 8) | (uint)n;
        }
        return true;
    }

    public static uint Parse(string text) => TryParse(text, out var v) ? v : throw new FormatException(text);

    public static uint FromAddress(IPAddress address)
    {
        var b = address.GetAddressBytes();
        if (b.Length != 4) throw new ArgumentException("IPv4 expected", nameof(address));
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static IPAddress ToAddress(uint value) =>
        new(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });

    public static string Format(uint value) =>
        $"{value >> 24}.{(value >> 16) & 255}.{(value >> 8) & 255}.{value & 255}";

    /// <summary>RFC1918 private address blocks.</summary>
    public static bool IsPrivate(uint v) =>
        (v & 0xFF000000) == 0x0A000000 ||      // 10.0.0.0/8
        (v & 0xFFF00000) == 0xAC100000 ||      // 172.16.0.0/12
        (v & 0xFFFF0000) == 0xC0A80000;        // 192.168.0.0/16

    public static bool IsLoopback(uint v) => (v & 0xFF000000) == 0x7F000000;
    public static bool IsMulticast(uint v) => (v & 0xF0000000) == 0xE0000000;
    public static bool IsReservedOrUnspecified(uint v) => v == 0 || v == 0xFFFFFFFF || (v & 0xF0000000) == 0xF0000000;
}

/// <summary>An IPv4 network (with its real prefix length; /24 is never assumed).</summary>
public readonly record struct Cidr(uint Network, int Prefix)
{
    public uint Mask => Prefix == 0 ? 0 : uint.MaxValue << (32 - Prefix);
    public uint Broadcast => Network | ~Mask;
    public long AddressCount => 1L << (32 - Prefix);
    public bool Contains(uint ip) => (ip & Mask) == Network;
    public bool Contains(Cidr other) => other.Prefix >= Prefix && Contains(other.Network);
    public override string ToString() => $"{Ipv4.Format(Network)}/{Prefix}";

    public static Cidr FromAddress(uint ip, int prefix)
    {
        if (prefix is < 0 or > 32) throw new ArgumentOutOfRangeException(nameof(prefix));
        var mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
        return new Cidr(ip & mask, prefix);
    }

    public static bool TryParse(string? text, out Cidr cidr)
    {
        cidr = default;
        if (text is null) return false;
        var slash = text.IndexOf('/');
        if (slash < 0) return false;
        if (!Ipv4.TryParse(text[..slash], out var ip)) return false;
        if (!int.TryParse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var p) || p is < 0 or > 32) return false;
        cidr = FromAddress(ip, p);
        return true;
    }
}
