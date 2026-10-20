using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Lanora.Net;

public enum NeighborState
{
    Unreachable = 0,
    Incomplete = 1,
    Probe = 2,
    Delay = 3,
    Stale = 4,
    Reachable = 5,
    Permanent = 6,
}

public sealed record NeighborEntry(uint Ip, uint InterfaceIndex, string? Mac, NeighborState State);

/// <summary>Local neighbor (ARP) table and route queries via iphlpapi. No administrator rights required.</summary>
internal static partial class NativeMethods
{
    private const ushort AfInet = 2;

    // MIB_IPNET_ROW2 (88 bytes on x64/x86): SOCKADDR_INET(28) IfIndex(4) LUID(8) PhysAddr[32] PhysLen(4) State(4) Flags(1+3) Reachability(4)
    private const int RowSize = 88;
    private const int OffIfIndex = 28;
    private const int OffPhys = 40;
    private const int OffPhysLen = 72;
    private const int OffState = 76;

    [LibraryImport("iphlpapi.dll")]
    private static partial int GetIpNetTable2(ushort family, out IntPtr table);

    [LibraryImport("iphlpapi.dll")]
    private static partial void FreeMibTable(IntPtr memory);

    [LibraryImport("iphlpapi.dll")]
    private static partial int GetBestInterface(uint destAddr, out uint bestIfIndex);

    public static List<NeighborEntry> GetNeighbors()
    {
        var result = new List<NeighborEntry>();
        var rc = GetIpNetTable2(AfInet, out var table);
        if (rc != 0) throw new Win32Exception(rc);
        try
        {
            var count = Marshal.ReadInt32(table);
            var rows = table + 8;
            for (var i = 0; i < count; i++)
            {
                var row = rows + i * RowSize;
                var family = (ushort)Marshal.ReadInt16(row, 0);
                if (family != AfInet) continue;
                var ip = ((uint)Marshal.ReadByte(row, 4) << 24) | ((uint)Marshal.ReadByte(row, 5) << 16) |
                         ((uint)Marshal.ReadByte(row, 6) << 8) | Marshal.ReadByte(row, 7);
                var ifIndex = (uint)Marshal.ReadInt32(row, OffIfIndex);
                var len = Marshal.ReadInt32(row, OffPhysLen);
                var state = (NeighborState)Marshal.ReadInt32(row, OffState);
                string? mac = null;
                if (len == 6)
                {
                    var bytes = new byte[6];
                    Marshal.Copy(row + OffPhys, bytes, 0, 6);
                    mac = MacAddress.Format(bytes);
                }
                result.Add(new NeighborEntry(ip, ifIndex, mac, state));
            }
        }
        finally
        {
            FreeMibTable(table);
        }
        return result;
    }

    /// <summary>Returns the best interface for the default route. No packets are sent.</summary>
    public static uint? GetDefaultRouteInterface()
    {
        // 8.8.8.8 is used only as the destination of a route table lookup; no traffic is sent.
        uint dest = 8 | (8 << 8) | (8 << 16) | (8u << 24);
        return GetBestInterface(dest, out var idx) == 0 ? idx : null;
    }
}

public static class MacAddress
{
    public static string? Format(ReadOnlySpan<byte> b)
    {
        if (b.Length != 6) return null;
        var allZero = true;
        var allFf = true;
        foreach (var x in b)
        {
            if (x != 0) allZero = false;
            if (x != 0xFF) allFf = false;
        }
        if (allZero || allFf) return null;
        return string.Join(':', b.ToArray().Select(x => x.ToString("X2")));
    }

    /// <summary>Locally administered (usually random/privacy) MAC address: the U/L bit of the first octet.</summary>
    public static bool IsLocallyAdministered(string mac) =>
        byte.TryParse(mac.AsSpan(0, 2), System.Globalization.NumberStyles.HexNumber, null, out var first) && (first & 0x02) != 0;

    public static bool IsMulticast(string mac) =>
        byte.TryParse(mac.AsSpan(0, 2), System.Globalization.NumberStyles.HexNumber, null, out var first) && (first & 0x01) != 0;
}
