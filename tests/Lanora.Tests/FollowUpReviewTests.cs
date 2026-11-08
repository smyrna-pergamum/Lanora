using System.Net;
using System.Net.Sockets;
using System.Text;
using Lanora.Infrastructure;
using Lanora.Net;
using Lanora.Scanning;
using Lanora.Scanning.Advanced;
using Lanora.Scanning.Native;

namespace Lanora.Tests;

/// <summary>Regression tests for the second review: service checks, IPv4 parsing, version strings and launch flags.</summary>
public class FollowUpReviewTests
{
    // ---------------- IPv4 / TargetValidator ----------------

    [Theory]
    [InlineData("١٩٢.١٦٨.١.٥")]   // Arabic-Indic digits
    [InlineData("１９２.１６８.１.５")] // full-width digits
    public void Non_ascii_digits_are_rejected_without_throwing(string target)
    {
        Assert.False(Ipv4.TryParse(target, out _));   // threw FormatException (HTTP 500)
        var ex = Assert.Throws<TargetValidationException>(() => TargetValidator.Validate(Fixtures.Adapter(), new[] { target }));
        Assert.Equal("TARGET_INVALID", ex.Code);
        var adv = Assert.Throws<ApiException>(() => AdvancedScanValidator.Build(
            new AdvancedScanRequest { Targets = { target }, Authorized = true }, Fixtures.Adapter(), _ => Array.Empty<string>()));
        Assert.Equal("ADV_TARGET_INVALID", adv.Code);
    }

    [Theory]
    [InlineData("192.168.1.20-+25")]
    [InlineData("192.168.1.20-025")]
    [InlineData("192.168.1.20-256")]
    public void Range_end_octet_is_parsed_strictly(string target)
    {
        var ex = Assert.Throws<TargetValidationException>(() => TargetValidator.Validate(Fixtures.Adapter(), new[] { target }));
        Assert.Equal("TARGET_INVALID", ex.Code);
    }

    [Fact]
    public void Range_with_spaces_around_the_dash_still_works()
    {
        Assert.Equal(6, TargetValidator.Validate(Fixtures.Adapter(), new[] { "192.168.1.20 - 25" }).Targets.Count);
        Assert.True(Ipv4.TryParseOctet("0", out var zero) && zero == 0);
        Assert.True(Ipv4.TryParseOctet("255", out var max) && max == 255);
    }

    // ---------------- http-title ----------------

    [Fact]
    public void Title_is_decoded_as_utf8_with_latin1_fallback()
    {
        var utf8 = Encoding.UTF8.GetBytes("HTTP/1.0 200 OK\r\n\r\n<html><title>Modem Arayüzü – Giriş</title>");
        Assert.Equal("Modem Arayüzü – Giriş", NativeScripts.ExtractTitle(utf8));

        var latin1 = Encoding.Latin1.GetBytes("HTTP/1.0 200 OK\r\n\r\n<title>Gerät Übersicht</title>");
        Assert.Equal("Gerät Übersicht", NativeScripts.ExtractTitle(latin1));

        // The read limit can cut a multi-byte character at the end; the title is still decoded as UTF-8.
        var cut = Encoding.UTF8.GetBytes("<title>Arayüz</title><p>ü").SkipLast(1).ToArray();
        Assert.Equal("Arayüz", NativeScripts.ExtractTitle(cut));
    }

    [Fact]
    public async Task Http_title_is_found_when_headers_and_body_arrive_separately()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            var stream = client.GetStream();
            var buffer = new byte[1024];
            await stream.ReadAsync(buffer);
            // Real devices often send the headers in their own packet; the old reader stopped at the first line break.
            await stream.WriteAsync("HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"u8.ToArray());
            await stream.FlushAsync();
            await Task.Delay(150);
            await stream.WriteAsync(Encoding.UTF8.GetBytes("<html><head><title>Yazıcı Durumu</title></head></html>"));
        });

        var scripts = new List<ScriptEvidence>();
        await NativeScripts.HttpTitle(Ipv4.Parse("127.0.0.1"), port, scripts, CancellationToken.None);
        await server;

        var evidence = Assert.Single(scripts);
        Assert.Equal($"http-title ({port})", evidence.Id);
        Assert.Equal("Yazıcı Durumu", evidence.Output);
    }

    // ---------------- Version strings ----------------

    [Fact]
    public void Http_user_agent_carries_the_application_version()
    {
        Assert.Equal("LANORA/" + ScanOrchestrator.AppVersion, NativeScripts.UserAgent);
        Assert.NotEqual("1.0.0", ScanOrchestrator.AppVersion); // fallback value means the assembly version was not set
    }

    // ---------------- Launch flags ----------------

    [Fact]
    public void Dev_url_file_is_resolved_to_a_full_path_in_debug_builds()
    {
        var opts = LaunchOptions.Parse(new[] { "--no-browser", "--dev-url-file", "launch.txt" });
        Assert.True(opts.NoBrowser);
#if DEBUG
        Assert.Equal(Path.GetFullPath("launch.txt"), opts.DevUrlFile);
#else
        Assert.Null(opts.DevUrlFile);
#endif
    }
}
