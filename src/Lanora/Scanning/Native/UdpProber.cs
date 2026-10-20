using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Lanora.Infrastructure;

namespace Lanora.Scanning.Native;

/// <summary>
/// Native (no administrator rights) UDP service scan. Sends protocol-specific probes to known UDP services:
/// reply → open; ICMP port unreachable (ConnectionReset on a connected socket) → closed; silence → open|filtered.
/// No raw sockets; works only with standard UDP sockets.
/// </summary>
public sealed class UdpProber
{
    /// <summary>UDP services for which we can build protocol-specific probes. Those that need multicast are flagged separately.</summary>
    public static readonly IReadOnlyDictionary<int, string> KnownServices = new Dictionary<int, string>
    {
        [53] = "DNS", [67] = "DHCP", [69] = "TFTP", [123] = "NTP", [137] = "NetBIOS-NS", [138] = "NetBIOS-DGM",
        [161] = "SNMP", [500] = "IKE", [520] = "RIP", [623] = "IPMI", [1900] = "SSDP", [5353] = "mDNS", [111] = "RPCbind",
    };

    // Services discovered via multicast: unicast silence is not evidence of being closed.
    private static readonly HashSet<int> MulticastOriented = new() { 5353, 1900, 137 };

    public static int[] DefaultPorts => new[] { 53, 123, 161, 137, 1900, 5353, 69, 111, 500, 520 };

    public async Task<ProbeResult> ProbeAsync(uint ip, int port, int timeoutMs, CancellationToken ct)
    {
        var payload = BuildProbe(port);
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.Connect(new IPEndPoint(Net.Ipv4.ToAddress(ip), port));
            var buffer = new byte[2048];
            // Two attempts: UDP loss is common. Each attempt has its own timeout token.
            for (var attempt = 0; attempt < 2; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeoutMs);
                try
                {
                    await socket.SendAsync(payload, SocketFlags.None, cts.Token).ConfigureAwait(false);
                    var n = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
                    return new ProbeResult(PortState.Open, n > 0 ? "udp_response" : "udp_empty_response", 0);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
                {
                    // ICMP port unreachable: port closed.
                    return new ProbeResult(PortState.Closed, "icmp_port_unreachable", 0);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    // This attempt timed out; move on to the next one.
                }
            }
        }
        catch (SocketException ex)
        {
            return new ProbeResult(PortState.Error, "udp_" + ex.SocketErrorCode.ToString().ToLowerInvariant(), 0);
        }
        // Silence: open or filtered. For multicast services unicast silence is additionally uncertain.
        return new ProbeResult(PortState.OpenFiltered, MulticastOriented.Contains(port) ? "multicast_service_silent" : "no_response", 0);
    }

    /// <summary>Protocol-specific probe bytes for a port. Empty datagram for unknown ports.</summary>
    internal static byte[] BuildProbe(int port) => port switch
    {
        53 => DnsQuery(),
        123 => NtpClient(),
        161 => SnmpGet(),
        137 => NetbiosNodeStatus(),
        1900 => Ssdp(),
        5353 => MdnsQuery(),
        69 => Tftp(),
        111 => RpcNull(),
        500 => IkeSa(),
        520 => RipRequest(),
        _ => new byte[] { 0x00 },
    };

    private static byte[] DnsQuery()
    {
        // Standard query: a simple root NS query instead of "version.bind".
        var m = new List<byte>();
        m.AddRange(new byte[] { 0x13, 0x37 });          // id
        m.AddRange(new byte[] { 0x01, 0x00 });          // flags: recursion desired
        m.AddRange(new byte[] { 0x00, 0x01 });          // qdcount
        m.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
        foreach (var label in new[] { "www", "example", "com" })
        {
            m.Add((byte)label.Length);
            m.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        m.Add(0x00);
        m.AddRange(new byte[] { 0x00, 0x01, 0x00, 0x01 }); // A, IN
        return m.ToArray();
    }

    private static byte[] NtpClient()
    {
        var p = new byte[48];
        p[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)
        return p;
    }

    /// <summary>sysDescr.0 = 1.3.6.1.2.1.1.1.0 (RFC 3418); scalar object with the ".0" instance identifier (RFC 1157).</summary>
    internal static readonly int[] SysDescrOid = { 1, 3, 6, 1, 2, 1, 1, 1, 0 };
    internal const int SnmpRequestId = 0x13371337;

    /// <summary>SNMPv1 GetRequest(sysDescr.0), community "public". Built with computed BER lengths.</summary>
    internal static byte[] SnmpGet()
    {
        var varBind = Tlv(0x30, Concat(Tlv(0x06, EncodeOid(SysDescrOid)), new byte[] { 0x05, 0x00 }));
        var varBindList = Tlv(0x30, varBind);
        var pdu = Tlv(0xA0, Concat(Integer(SnmpRequestId), Integer(0), Integer(0), varBindList));
        return Tlv(0x30, Concat(Integer(0), Tlv(0x04, Encoding.ASCII.GetBytes("public")), pdu));
    }

    internal static byte[] EncodeOid(int[] oid)
    {
        var bytes = new List<byte> { (byte)(oid[0] * 40 + oid[1]) };
        foreach (var arc in oid.Skip(2))
        {
            var stack = new Stack<byte>();
            var v = arc;
            stack.Push((byte)(v & 0x7F));
            while ((v >>= 7) > 0) stack.Push((byte)(0x80 | (v & 0x7F)));
            bytes.AddRange(stack);
        }
        return bytes.ToArray();
    }

    private static byte[] Integer(int value)
    {
        var raw = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(raw);
        var i = 0;
        // Shortest two's-complement encoding.
        while (i < raw.Length - 1 && ((raw[i] == 0x00 && (raw[i + 1] & 0x80) == 0) || (raw[i] == 0xFF && (raw[i + 1] & 0x80) != 0))) i++;
        return Tlv(0x02, raw[i..]);
    }

    private static byte[] Tlv(byte tag, byte[] content)
    {
        var len = content.Length;
        byte[] lenBytes = len < 0x80 ? new[] { (byte)len } : len <= 0xFF ? new byte[] { 0x81, (byte)len } : new byte[] { 0x82, (byte)(len >> 8), (byte)len };
        return Concat(new[] { tag }, lenBytes, content);
    }

    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(x => x).ToArray();

    private static byte[] NetbiosNodeStatus()
    {
        var p = new List<byte>();
        p.AddRange(new byte[] { 0x13, 0x37, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
        p.Add(0x20); // encoded "*"
        p.AddRange(System.Text.Encoding.ASCII.GetBytes("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        p.Add(0x00);
        p.AddRange(new byte[] { 0x00, 0x21, 0x00, 0x01 }); // NBSTAT, IN
        return p.ToArray();
    }

    private static byte[] Ssdp()
    {
        const string s = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
        return System.Text.Encoding.ASCII.GetBytes(s);
    }

    private static byte[] MdnsQuery()
    {
        var m = new List<byte>();
        m.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
        foreach (var label in new[] { "_services", "_dns-sd", "_udp", "local" })
        {
            m.Add((byte)label.Length);
            m.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        m.Add(0x00);
        m.AddRange(new byte[] { 0x00, 0x0C, 0x00, 0x01 }); // PTR, IN
        return m.ToArray();
    }

    private static byte[] Tftp()
    {
        // RRQ "lanora" octet
        var m = new List<byte> { 0x00, 0x01 };
        m.AddRange(System.Text.Encoding.ASCII.GetBytes("lanora"));
        m.Add(0x00);
        m.AddRange(System.Text.Encoding.ASCII.GetBytes("octet"));
        m.Add(0x00);
        return m.ToArray();
    }

    private static byte[] RpcNull()
    {
        var p = new byte[56];
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(0), 0x13371337); // xid
        // CALL(0), rpcvers=2, prog=100000 (portmap), vers=2, proc=0
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(8), 2);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(12), 100000);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(16), 2);
        return p;
    }

    private static byte[] IkeSa()
    {
        var p = new byte[28];
        BinaryPrimitives.WriteUInt64BigEndian(p.AsSpan(0), 0x1337133713371337); // initiator cookie
        p[16] = 0x01; // SA payload
        p[17] = 0x10; // version
        p[18] = 0x02; // exchange: identity protect
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(24), 28);
        return p;
    }

    private static byte[] RipRequest() => new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };

    public static string? ServiceName(int port) => KnownServices.TryGetValue(port, out var s) ? s : null;
}
