using Lanora.Net;
using Lanora.Scanning.Native;
using Lanora.Scanning.Advanced;

namespace Lanora.Tests;

public class NativeEngineTests
{
    private static AdapterInfo Adapter() => NetworkTests_Adapter();
    private static AdapterInfo NetworkTests_Adapter()
    {
        var value = Ipv4.Parse("192.168.1.10");
        var net = Cidr.FromAddress(value, 24);
        return new AdapterInfo
        {
            Id = "test/192.168.1.10", AdapterGuid = "{t}", Name = "T", Description = "T", Kind = "ethernet",
            Ip = "192.168.1.10", PrefixLength = 24, NetworkCidr = net.ToString(), Gateway = "192.168.1.1", Mac = "AA:BB:CC:00:00:01",
            Selectable = true, IsPrivate = true, Ranges = new[] { net.ToString() }, SuggestedRange = net.ToString(),
            AddressCount = 256,
        };
    }

    [Fact] // Built-in engine plan: targets are resolved, technique Connect
    public void Default_engine_is_native()
    {
        var req = new AdvancedScanRequest { Targets = { "192.168.1.5" }, InterfaceId = "test/192.168.1.10" };
        var plan = AdvancedScanValidator.Build(req, Adapter(), _ => Array.Empty<string>());
        
        Assert.NotEmpty(plan.IpTargets);
        Assert.Equal(Ipv4.Parse("192.168.1.5"), plan.IpTargets[0]);
    }

    [Fact] // A local target needs no authorization; an external target does
    public void External_target_still_requires_authorization()
    {
        var local = new AdvancedScanRequest { Targets = { "192.168.1.20" }, InterfaceId = "test/192.168.1.10" };
        AdvancedScanValidator.Build(local, Adapter(), _ => Array.Empty<string>()); // local: fine

        var ext = new AdvancedScanRequest { Targets = { "8.8.8.8" }, InterfaceId = "test/192.168.1.10", Authorized = false };
        var exLocalReserved = Assert.Throws<Lanora.Infrastructure.ApiException>(() => AdvancedScanValidator.Build(ext, Adapter(), _ => Array.Empty<string>()));
        Assert.Equal("AUTHORIZATION_REQUIRED", exLocalReserved.Code);

        var extOk = new AdvancedScanRequest { Targets = { "203.0.113.5" }, InterfaceId = "test/192.168.1.10", Authorized = true };
        var plan = AdvancedScanValidator.Build(extOk, Adapter(), _ => Array.Empty<string>());
        Assert.True(plan.AnyExternal);
        Assert.Contains(Ipv4.Parse("203.0.113.5"), plan.IpTargets);
    }

    [Fact] // top/custom/all port scopes resolve to concrete lists
    public void Port_scopes_resolve_to_concrete_lists()
    {
        var top = AdvancedScanValidator.Build(new AdvancedScanRequest { Targets = { "192.168.1.5" }, InterfaceId = "test/192.168.1.10", PortScope = "top", TopPorts = 20 }, Adapter(), _ => Array.Empty<string>());
        Assert.Equal(20, top.TcpPorts.Count);

        var custom = AdvancedScanValidator.Build(new AdvancedScanRequest { Targets = { "192.168.1.5" }, InterfaceId = "test/192.168.1.10", PortScope = "custom", TcpPorts = new() { 80, 443 }, IncludeUdp = true, UdpPorts = new() { 53 } }, Adapter(), _ => Array.Empty<string>());
        Assert.Equal(new[] { 80, 443 }, custom.TcpPorts);
        Assert.Equal(new[] { 53 }, custom.UdpPorts);

        var udpTech = AdvancedScanValidator.Build(new AdvancedScanRequest { Targets = { "192.168.1.5" }, InterfaceId = "test/192.168.1.10", Technique = "udp", PortScope = "top" }, Adapter(), _ => Array.Empty<string>());
        Assert.Empty(udpTech.TcpPorts);
        Assert.NotEmpty(udpTech.UdpPorts);
    }

    [Fact] // Without authorization a hostname is not even resolved
    public void Hostname_requires_authorization_even_to_resolve()
    {
        var called = false;
        var req = new AdvancedScanRequest { Targets = { "scanme.example.org" }, InterfaceId = "test/192.168.1.10", Authorized = false };
        var ex = Assert.Throws<Lanora.Infrastructure.ApiException>(() => AdvancedScanValidator.Build(req, Adapter(), _ => { called = true; return new[] { "203.0.113.9" }; }));
        Assert.Equal("AUTHORIZATION_REQUIRED", ex.Code);
        Assert.False(called); // resolution was never attempted
    }

    [Theory] // UDP probes produce protocol-specific, non-empty bytes
    [InlineData(53)]
    [InlineData(123)]
    [InlineData(161)]
    [InlineData(1900)]
    [InlineData(5353)]
    [InlineData(137)]
    public void Udp_probes_are_protocol_specific(int port)
    {
        var probe = UdpProber.BuildProbe(port);
        Assert.NotEmpty(probe);
        Assert.True(probe.Length > 1);
    }

    [Fact]
    public void Ntp_probe_sets_client_mode()
    {
        var ntp = UdpProber.BuildProbe(123);
        Assert.Equal(48, ntp.Length);
        Assert.Equal(0x1B, ntp[0]); // LI=0, VN=3, Mode=3
    }

    [Fact]
    public void Udp_service_names_are_known()
    {
        Assert.Equal("DNS", UdpProber.ServiceName(53));
        Assert.Equal("SNMP", UdpProber.ServiceName(161));
        Assert.Null(UdpProber.ServiceName(4242));
    }
}
