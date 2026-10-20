using System.Net;
using Lanora.Api;
using Lanora.Data;
using Lanora.Infrastructure;
using Lanora.Net;
using Lanora.Reports;
using Lanora.Risk;
using Lanora.Scanning;
using Lanora.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Lanora;

/// <summary>
/// Local host process: ASP.NET Core listens only on 127.0.0.1, on a dynamic port assigned by the OS at bind time
/// (SEC01). Because an empty configuration is used, environment variables or appsettings cannot enable external listening.
/// </summary>
public sealed class LanoraHost : IAsyncDisposable
{
    private readonly WebApplication _app;

    private LanoraHost(WebApplication app, int port, SessionManager sessions, ScanOrchestrator orchestrator, Database db, SettingsStore settings)
    {
        _app = app;
        Port = port;
        Sessions = sessions;
        Orchestrator = orchestrator;
        Db = db;
        Settings = settings;
    }

    public int Port { get; }
    public SessionManager Sessions { get; }
    public ScanOrchestrator Orchestrator { get; }
    public Database Db { get; }
    public SettingsStore Settings { get; }

    /// <summary>Launch URL handed to the browser; the secret travels only in the URL fragment (never sent to the server).</summary>
    public string CreateLaunchUrl() => $"http://127.0.0.1:{Port}/#k={Sessions.CreateBootstrapSecret()}";

    public static async Task<LanoraHost> StartAsync(AppPaths paths)
    {
        var db = new Database(paths);
        db.Initialize();

        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions
        {
            ApplicationName = "Lanora",
            ContentRootPath = AppContext.BaseDirectory,
        });
        builder.WebHost.UseKestrelCore();
        builder.WebHost.ConfigureKestrel(o =>
        {
            o.AddServerHeader = false;
            o.Limits.MaxRequestBodySize = 64 * 1024;
            o.Limits.MaxRequestHeadersTotalSize = 32 * 1024;
            o.Listen(IPAddress.Loopback, 0);
        });
        builder.Services.AddRouting();

        var port = 0;
        var sessions = new SessionManager();
        var catalog = new PortCatalog();
        var rules = new Ruleset();
        var risk = new RiskEngine(rules);
        var store = new ScanStore(db);
        var settings = new SettingsStore(db);
        var badges = new BadgeService(db);
        var net = new NetworkInfoService();
        var oui = new OuiDatabase();
        var orchestrator = new ScanOrchestrator(net, catalog, risk, store, badges, oui, new SocketBackend(), new ServiceProber(), db);
        var retention = new RetentionService(store, settings);

        builder.Services.AddSingleton(paths).AddSingleton(db).AddSingleton(sessions).AddSingleton(catalog).AddSingleton(rules)
            .AddSingleton(risk).AddSingleton(store).AddSingleton(settings).AddSingleton(badges).AddSingleton(net).AddSingleton(oui)
            .AddSingleton(orchestrator).AddSingleton(retention).AddSingleton(new ReportBuilder(store, rules, orchestrator));

        var app = builder.Build();
        app.UseMiddleware<ErrorMiddleware>();
        app.UseMiddleware<RequestGuard>(sessions, (Func<int>)(() => port));
        app.UseRouting();
        MapStatic(app);
        Endpoints.Map(app);

        await app.StartAsync().ConfigureAwait(false);
        var address = app.Urls.Single();
        var uri = new Uri(address);
        if (!IPAddress.IsLoopback(IPAddress.Parse(uri.Host)) || uri.Host != "127.0.0.1")
            throw new InvalidOperationException("Refusing to run: listener is not bound to 127.0.0.1");
        port = uri.Port;
        AppLog.Info("host", $"listening on 127.0.0.1:{port}");
        return new LanoraHost(app, port, sessions, orchestrator, db, settings);
    }

    private static void MapStatic(WebApplication app)
    {
        var files = new Dictionary<string, (string Resource, string Type)>
        {
            ["/"] = ("web/index.html", "text/html; charset=utf-8"),
            ["/index.html"] = ("web/index.html", "text/html; charset=utf-8"),
            ["/app.js"] = ("web/app.js", "text/javascript; charset=utf-8"),
            ["/app.css"] = ("web/app.css", "text/css; charset=utf-8"),
            ["/favicon.svg"] = ("web/favicon.svg", "image/svg+xml"),
        };
        foreach (var (path, (resource, type)) in files)
        {
            app.MapGet(path, async (HttpContext ctx) =>
            {
                await using var s = Res.Open(resource);
                if (s is null)
                {
                    ctx.Response.StatusCode = 404;
                    return;
                }
                ctx.Response.ContentType = type;
                ctx.Response.Headers.CacheControl = "no-cache";
                await s.CopyToAsync(ctx.Response.Body);
            });
        }
    }

    /// <summary>SEC06: Exit cancels the scan and closes the listener and the database.</summary>
    public async ValueTask DisposeAsync()
    {
        try { await Orchestrator.ShutdownAsync().ConfigureAwait(false); } catch (Exception ex) { AppLog.Error("shutdown", ex); }
        Sessions.RevokeAll();
        try { await _app.StopAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false); } catch (Exception ex) { AppLog.Error("shutdown", ex); }
        await _app.DisposeAsync().ConfigureAwait(false);
        Db.Dispose();
        AppLog.Info("host", "stopped");
    }
}
