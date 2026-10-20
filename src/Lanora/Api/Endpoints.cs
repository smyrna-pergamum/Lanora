using System.Text.Json;
using Lanora.Data;
using Lanora.Infrastructure;
using Lanora.Net;
using Lanora.Reports;
using Lanora.Risk;
using Lanora.Scanning;
using Lanora.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Lanora.Api;

public static class ApiResults
{
    public static Task Write(HttpContext ctx, int status, string code, object? details = null)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        return ctx.Response.WriteAsync(Json.Serialize(new { code, message_key = "error." + code, details }));
    }

    public static IResult Ok(object? value) => Results.Text(Json.Serialize(value), "application/json; charset=utf-8");

    public static IResult Status(int status, object? value) =>
        Results.Text(Json.Serialize(value), "application/json; charset=utf-8", statusCode: status);
}

/// <summary>Maps errors to a fixed code + message_key + safe detail; no stack trace is returned.</summary>
public sealed class ErrorMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext ctx)
    {
        try
        {
            await next(ctx);
        }
        catch (ApiException ex)
        {
            if (!ctx.Response.HasStarted) await ApiResults.Write(ctx, ex.Status, ex.Code, ex.Details);
        }
        catch (BadHttpRequestException)
        {
            if (!ctx.Response.HasStarted) await ApiResults.Write(ctx, 400, "BAD_REQUEST");
        }
        catch (JsonException)
        {
            if (!ctx.Response.HasStarted) await ApiResults.Write(ctx, 400, "INVALID_JSON");
        }
        catch (OperationCanceledException) when (ctx.RequestAborted.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            AppLog.Error("api " + ctx.Request.Method + " " + ctx.Request.Path, ex);
            if (!ctx.Response.HasStarted) await ApiResults.Write(ctx, 500, "INTERNAL_ERROR");
        }
    }
}

public static class Endpoints
{
    private static readonly HashSet<string> DeviceTypes = new()
    {
        "computer", "laptop", "phone", "tablet", "tv", "media", "speaker", "printer", "storage", "router", "camera", "iot", "game", "other",
    };

    public static void Map(WebApplication app)
    {
        var api = app.MapGroup("/api/v1");

        api.MapPost("/session/bootstrap", async (HttpContext ctx, SessionManager sessions) =>
        {
            var body = await ReadBody(ctx);
            var secret = body.TryGetProperty("secret", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null;
            var token = sessions.Redeem(secret);
            if (token is null) throw new ApiException(401, "BOOTSTRAP_INVALID");
            return ApiResults.Ok(new { token });
        });

        api.MapGet("/network-interfaces", (NetworkInfoService net) => ApiResults.Ok(new { items = net.GetAdapters() }));

        api.MapGet("/capabilities", (PortCatalog catalog, RiskEngine risk, ScanOrchestrator orch, Database db) =>
        {
            return ApiResults.Ok(new
            {
                app_version = ScanOrchestrator.AppVersion,
                engine_version = orch.EngineVersion,
                ruleset_version = risk.Version,
                port_list_version = catalog.Version,
                elevated = false,
                scanning_available = !db.MigrationFailed,
                limits = new { max_targets = TargetValidator.MaxAddresses, catalog.Rate.GlobalConcurrency, catalog.Rate.PerHostConcurrency, catalog.Rate.NewConnectionsPerSecond, catalog.Rate.TimeBudgetMinutes },
                profiles = catalog.Profiles.Select(p => new
                {
                    id = p.Id,
                    protocol = p.Protocol,
                    available = p.Available != false,
                    port_count = p.Ports?.Length,
                    ports = p.Ports,
                    timeout_ms = p.TimeoutMs,
                    retries = p.Retries,
                    max_ports = p.MaxPorts,
                    max_attempts = p.MaxAttempts,
                    udp_ports = p.UdpPorts,
                    requires_elevation = p.Id == "advanced",
                    requires = p.Requires,
                }),
                advanced = new
                {
                    // The built-in advanced scan engine is always available; no installation required.
                    available = true,
                    techniques = new[] { "connect", "udp" },
                    service_checks = new[] { "http-title", "ssl-enum", "ssh-banner", "ftp-anon" },
                    port_scopes = new[] { "top", "custom", "all" },
                    features = new[] { "udp", "os_detection", "traceroute", "reverse_dns", "service_checks", "external_targets", "hostname_targets" },
                    max_targets = Lanora.Scanning.Advanced.AdvancedScanValidator.MaxTargets,
                },
            });
        });

        // Advanced scan preview: resolved targets, authorization requirement and planned ports.
        api.MapPost("/advanced-scans/preview", async (HttpContext ctx, ScanOrchestrator orch) =>
        {
            var req = await ReadAs<Lanora.Scanning.Advanced.AdvancedScanRequest>(ctx);
            var plan = orch.BuildAdvancedPlan(req);
            return ApiResults.Ok(new
            {
                targets = plan.Targets.Select(t => new { input = t.Input, resolved = t.Resolved, local = t.IsLocal, external = t.IsExternal, hostname = t.IsHostname }),
                target_count = plan.IpTargets.Count,
                tcp_port_count = plan.TcpPorts.Count,
                udp_port_count = plan.UdpPorts.Count,
                any_external = plan.AnyExternal,
                authorization_required = plan.AuthorizationRequired,
                effective_technique = plan.Technique.ToString().ToLowerInvariant(),
                udp = plan.UdpPorts.Count > 0,
                os_detection = plan.OsDetection,
                traceroute = plan.Traceroute,
                service_checks = plan.ServiceChecks,
            });
        });

        api.MapPost("/advanced-scans", async (HttpContext ctx, ScanOrchestrator orch) =>
        {
            var req = await ReadAs<Lanora.Scanning.Advanced.AdvancedScanRequest>(ctx);
            var (id, existing) = await orch.StartAdvancedAsync(req, ctx.Request.Headers["Idempotency-Key"].ToString());
            return ApiResults.Status(existing ? 200 : 202, new { scan_id = id, existing });
        });

        // Review targets before starting (FR02) and the probe budget.
        api.MapPost("/scans/preview", async (HttpContext ctx, ScanOrchestrator orch) =>
        {
            var req = await ReadAs<ScanRequest>(ctx);
            var plan = orch.BuildPlan(req);
            return ApiResults.Ok(new
            {
                interface_id = plan.Adapter.Id,
                network_cidr = plan.Adapter.NetworkCidr,
                profile_id = plan.ProfileId,
                port_count = plan.Ports.Count,
                targets = plan.Targets.Targets.Select(Ipv4.Format),
                excluded = plan.Targets.Excluded,
                local_ip = Ipv4.Format(plan.Targets.LocalIp),
                gateway = plan.Targets.Gateway is { } g ? Ipv4.Format(g) : null,
                max_attempts = plan.MaxAttempts,
                timeout_ms = plan.TimeoutMs,
                retries = plan.Retries,
                requires_elevation = false,
            });
        });

        api.MapPost("/scans", async (HttpContext ctx, ScanOrchestrator orch) =>
        {
            var req = await ReadAs<ScanRequest>(ctx);
            var (id, existing) = await orch.StartAsync(req, ctx.Request.Headers["Idempotency-Key"].ToString());
            return ApiResults.Status(existing ? 200 : 202, new { scan_id = id, existing });
        });

        api.MapGet("/scans", (HttpContext ctx, ScanStore store) =>
        {
            var q = ctx.Request.Query;
            var page = Math.Max(1, int.TryParse(q["page"], out var p) ? p : 1);
            var size = Math.Clamp(int.TryParse(q["page_size"], out var ps) ? ps : 25, 1, 100);
            string? from = DateParam(q["from"]);
            string? to = DateParam(q["to"], endOfDay: true);
            var scope = string.IsNullOrEmpty(q["network_scope_id"]) ? null : q["network_scope_id"].ToString();
            var (items, total) = store.ListScans(scope, from, to, page, size);
            return ApiResults.Ok(new { items, total, page, page_size = size, scopes = store.ListScopes() });
        });

        api.MapGet("/scans/{id}", (string id, ScanStore store, ScanOrchestrator orch) =>
        {
            var job = orch.GetJob(id);
            var summary = store.GetSummary(id) ?? throw new ApiException(404, "SCAN_NOT_FOUND");
            var active = job is not null && ScanStates.IsActive(job.State);
            return ApiResults.Ok(new
            {
                summary,
                progress = active ? job!.Progress() : null,
                hosts = active ? new List<HostDto>() : store.GetHosts(id),
            });
        });

        api.MapGet("/scans/{id}/events", ServeEvents);

        api.MapPost("/scans/{id}/cancel", (string id, ScanOrchestrator orch) =>
        {
            if (!orch.Cancel(id)) throw new ApiException(404, "SCAN_NOT_FOUND");
            return ApiResults.Status(202, new { scan_id = id, requested = true });
        });

        api.MapDelete("/scans/{id}", async (string id, ScanStore store, ScanOrchestrator orch) =>
        {
            if (orch.Active?.Id == id) throw new ApiException(409, "SCAN_ACTIVE");
            if (!await store.DeleteScanAsync(id)) throw new ApiException(404, "SCAN_NOT_FOUND");
            return ApiResults.Ok(new { deleted = id });
        });

        api.MapGet("/scans/{id}/compare/{other}", (string id, string other, ScanStore store) =>
            ApiResults.Ok(store.Compare(id, other) ?? throw new ApiException(404, "SCAN_NOT_FOUND")));

        api.MapGet("/scans/{id}/compare", (string id, ScanStore store) =>
        {
            var prev = store.PreviousComparable(id);
            return ApiResults.Ok(prev is null ? new { scan_id = id, previous_scan_id = (string?)null } : store.Compare(id, prev));
        });

        api.MapGet("/scans/{id}/report", (HttpContext ctx, string id, ReportBuilder builder) =>
        {
            var format = ctx.Request.Query["format"].ToString();
            var lang = ctx.Request.Query["lang"].ToString();
            if (format is not ("pdf" or "xlsx")) throw new ApiException(400, "REPORT_FORMAT_INVALID");
            if (lang is not ("en" or "tr" or "de")) throw new ApiException(400, "REPORT_LANG_INVALID");
            var data = builder.Build(id, lang) ?? throw new ApiException(404, "SCAN_NOT_FOUND");
            var bytes = format == "pdf" ? PdfReport.Render(data) : XlsxReport.Render(data);
            var type = format == "pdf" ? "application/pdf" : "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
            return Results.File(bytes, type, ReportBuilder.FileName(data, format));
        });

        api.MapGet("/dashboard", (HttpContext ctx, ScanStore store, ScanOrchestrator orch, BadgeService badges) =>
        {
            var scope = ctx.Request.Query["network_scope_id"].ToString();
            var scopeId = string.IsNullOrEmpty(scope) ? null : scope;
            var displayId = store.LatestDisplayScan(scopeId);
            var display = displayId is null ? null : store.GetSummary(displayId);
            scopeId ??= display?.NetworkScopeId;
            var latestId = store.LatestScan(scopeId);
            var latest = latestId is null || latestId == displayId ? null : store.GetSummary(latestId);
            var active = orch.Active;
            return ApiResults.Ok(new
            {
                scan = display,
                hosts = displayId is null ? new List<HostDto>() : store.GetHosts(displayId),
                latest_other = latest,
                active = active is null ? null : active.Progress(),
                badges = badges.Get(scopeId),
                network_scope_id = scopeId,
            });
        });

        api.MapGet("/devices/{id}", (string id, ScanStore store) =>
            ApiResults.Ok(store.GetDevice(id) ?? throw new ApiException(404, "DEVICE_NOT_FOUND")));

        api.MapPatch("/devices/{id}", async (HttpContext ctx, string id, ScanStore store) =>
        {
            if (!store.DeviceExists(id)) throw new ApiException(404, "DEVICE_NOT_FOUND");
            var body = await ReadBody(ctx);
            var target = id;
            if (body.TryGetProperty("merge_into", out var m) && m.ValueKind == JsonValueKind.String)
            {
                var other = m.GetString()!;
                if (!store.DeviceExists(other)) throw new ApiException(404, "DEVICE_NOT_FOUND");
                try { target = await store.MergeAsync(id, other); }
                catch (InvalidOperationException ex) { throw new ApiException(409, ex.Message); }
            }
            if (body.TryGetProperty("unmerge", out var u) && u.ValueKind == JsonValueKind.True)
                await store.UnmergeAsync(id);

            var setName = body.TryGetProperty("custom_name", out var n);
            string? name = null;
            if (setName)
            {
                if (n.ValueKind == JsonValueKind.Null) name = null;
                else if (n.ValueKind == JsonValueKind.String)
                {
                    name = SafeText.Clean(n.GetString(), 200);
                    if (string.IsNullOrEmpty(name) || name.Length > 80) throw new ApiException(400, "NAME_INVALID", new { max = 80 });
                }
                else throw new ApiException(400, "NAME_INVALID");
            }
            var setType = body.TryGetProperty("user_type", out var tp);
            string? type = null;
            if (setType && tp.ValueKind == JsonValueKind.String)
            {
                type = tp.GetString();
                if (!DeviceTypes.Contains(type!)) throw new ApiException(400, "TYPE_INVALID");
            }
            else if (setType && tp.ValueKind != JsonValueKind.Null)
            {
                throw new ApiException(400, "TYPE_INVALID");
            }
            var setNotes = body.TryGetProperty("notes", out var nt);
            string? notes = null;
            if (setNotes && nt.ValueKind == JsonValueKind.String)
            {
                notes = SafeText.Clean(nt.GetString(), 1000);
            }
            else if (setNotes && nt.ValueKind != JsonValueKind.Null)
            {
                throw new ApiException(400, "NOTES_INVALID");
            }
            if (setName || setType || setNotes) target = await store.UpdateDeviceAsync(target, name, setName, type, setType, notes, setNotes);
            return ApiResults.Ok(store.GetDevice(target));
        });

        api.MapPut("/devices/{id}/services/{protocol}/{port:int}", async (HttpContext ctx, string id, string protocol, int port, ScanStore store) =>
        {
            if (protocol is not ("tcp" or "udp") || port is < 1 or > 65535) throw new ApiException(400, "SERVICE_INVALID");
            if (!store.DeviceExists(id)) throw new ApiException(404, "DEVICE_NOT_FOUND");
            var body = await ReadBody(ctx);
            var required = body.TryGetProperty("required", out var r) && r.ValueKind == JsonValueKind.True;
            await store.SetServiceRequiredAsync(id, protocol, port, required);
            return ApiResults.Ok(new { device_id = id, protocol, port, required });
        });

        api.MapGet("/guide", (HttpContext ctx) =>
        {
            var lang = ctx.Request.Query["lang"].ToString();
            var i = Ruleset.LangIndex(lang);
            var guide = Res.ReadJson<GuideFile>("res/guide.json");
            return ApiResults.Ok(new
            {
                version = guide.Version,
                lang = new[] { "en", "tr", "de" }[i],
                faq = guide.Faq.Select(f => new { q = f.Q[i], a = f.A[i] }),
                tips = guide.Tips.Select(t => t[i]),
            });
        });

        api.MapGet("/rules", (HttpContext ctx, Ruleset rules) =>
        {
            var i = Ruleset.LangIndex(ctx.Request.Query["lang"].ToString());
            return ApiResults.Ok(new
            {
                version = rules.Version,
                rules = rules.File.Rules.Select(r => new
                {
                    id = r.Id, severity = r.Severity, penalty = r.Penalty, protocol = r.Protocol, ports = r.Ports,
                    title = r.Title[i], observed = r.Observed[i], meaning = r.Meaning[i], action = r.Action[i], verify = r.Verify[i],
                }),
            });
        });

        api.MapGet("/settings", (SettingsStore settings) => ApiResults.Ok(settings.Get()));

        api.MapPatch("/settings", async (HttpContext ctx, SettingsStore settings, RetentionService retention) =>
        {
            var body = await ReadBody(ctx);
            var values = new Dictionary<string, string>();
            if (body.TryGetProperty("lang", out var l))
            {
                if (AsString(l) is not { } lang || !SettingsStore.Languages.Contains(lang)) throw new ApiException(400, "SETTING_INVALID", new { field = "lang" });
                values["lang"] = lang;
            }
            if (body.TryGetProperty("theme", out var th))
            {
                if (AsString(th) is not ("light" or "dark")) throw new ApiException(400, "SETTING_INVALID", new { field = "theme" });
                values["theme"] = AsString(th)!;
            }
            if (body.TryGetProperty("retention", out var rt))
            {
                if (AsString(rt) is not { } ret || !SettingsStore.Retentions.Contains(ret)) throw new ApiException(400, "SETTING_INVALID", new { field = "retention" });
                values["retention"] = ret;
            }
            if (body.TryGetProperty("tips", out var tp))
            {
                if (tp.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new ApiException(400, "SETTING_INVALID", new { field = "tips" });
                values["tips"] = tp.GetBoolean() ? "1" : "0";
            }
            if (body.TryGetProperty("default_profile", out var dp))
            {
                if (AsString(dp) is not ("quick" or "standard" or "custom")) throw new ApiException(400, "SETTING_INVALID", new { field = "default_profile" });
                values["default_profile"] = AsString(dp)!;
            }
            await settings.SetAsync(values);
            if (values.ContainsKey("retention")) await retention.RunAsync();
            return ApiResults.Ok(settings.Get());
        });

        api.MapPost("/data/backup", (Database db) =>
        {
            var path = db.Backup("manual");
            return ApiResults.Ok(new { file = Path.GetFileName(path) });
        });

        // FR27: Delete all data (labels, settings, logs and managed backups). Downloaded reports are out of scope.
        api.MapPost("/data/delete-all", async (HttpContext ctx, ScanStore store, Database db, ScanOrchestrator orch) =>
        {
            var body = await ReadBody(ctx);
            if (!(body.TryGetProperty("confirm", out var c) && AsString(c) == "DELETE_ALL")) throw new ApiException(400, "CONFIRMATION_REQUIRED");
            if (orch.Active is not null) throw new ApiException(409, "SCAN_ACTIVE");
            await store.DeleteAllAsync();
            db.DeleteManagedBackups();
            AppLog.DeleteAll();
            return ApiResults.Ok(new { deleted = true, downloaded_reports_affected = false });
        });

        api.MapFallback(() => ApiResults.Status(404, new { code = "NOT_FOUND", message_key = "error.NOT_FOUND", details = (object?)null }));
    }

    private static async Task ServeEvents(HttpContext ctx, string id, ScanOrchestrator orch, ScanStore store)
    {
        var job = orch.GetJob(id);
        if (job is null)
        {
            var summary = store.GetSummary(id) ?? throw new ApiException(404, "SCAN_NOT_FOUND");
            ctx.Response.ContentType = "text/event-stream";
            await ctx.Response.WriteAsync($"event: scan_finished\ndata: {Json.Serialize(new { scan_id = id, state = summary.State, reason_code = summary.ReasonCode, summary })}\n\n");
            return;
        }

        ctx.Response.ContentType = "text/event-stream";
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers["X-Accel-Buffering"] = "no";
        long last = 0;
        if (long.TryParse(ctx.Request.Headers["Last-Event-ID"].ToString(), out var h)) last = h;
        else if (long.TryParse(ctx.Request.Query["last_event_id"].ToString(), out var qv)) last = qv;
        var ct = ctx.RequestAborted;

        await ctx.Response.WriteAsync($"event: snapshot\ndata: {Json.Serialize(job.Progress())}\n\n", ct);
        await ctx.Response.Body.FlushAsync(ct);
        while (!ct.IsCancellationRequested)
        {
            var (events, gap, next) = job.Events.After(last);
            if (gap) await ctx.Response.WriteAsync($"event: resync\ndata: {Json.Serialize(job.Progress())}\n\n", ct);
            foreach (var e in events)
            {
                await ctx.Response.WriteAsync($"id: {e.Id}\nevent: {e.Type}\ndata: {e.Data}\n\n", ct);
                last = e.Id;
            }
            await ctx.Response.Body.FlushAsync(ct);
            if (job.Events.Finished && job.Events.After(last).Events.Count == 0) break;
            var finished = await Task.WhenAny(next, Task.Delay(TimeSpan.FromSeconds(15), ct)).ConfigureAwait(false);
            if (finished != next && !ct.IsCancellationRequested)
            {
                await ctx.Response.WriteAsync(": keepalive\n\n", ct);
                await ctx.Response.Body.FlushAsync(ct);
            }
        }
    }

    /// <summary>Returns the value only if it is a JSON string; null for other types (the caller returns 400, not 500).</summary>
    private static string? AsString(JsonElement e) => e.ValueKind == JsonValueKind.String ? e.GetString() : null;

    private static string? DateParam(string? value, bool endOfDay = false)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (!DateOnly.TryParseExact(value, "yyyy-MM-dd", out var d)) throw new ApiException(400, "DATE_INVALID");
        var local = d.ToDateTime(TimeOnly.MinValue, DateTimeKind.Local);
        if (endOfDay) local = local.AddDays(1);
        return Clock.Iso(new DateTimeOffset(local));
    }

    private static async Task<JsonElement> ReadBody(HttpContext ctx)
    {
        using var doc = await JsonDocument.ParseAsync(ctx.Request.Body, cancellationToken: ctx.RequestAborted);
        if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new ApiException(400, "INVALID_JSON");
        return doc.RootElement.Clone();
    }

    private static async Task<T> ReadAs<T>(HttpContext ctx) where T : new()
    {
        var body = await ReadBody(ctx);
        return body.Deserialize<T>(Json.Options) ?? new T();
    }
}

public sealed class GuideFile
{
    public string Version { get; init; } = "";
    public List<FaqEntry> Faq { get; init; } = new();
    public List<string[]> Tips { get; init; } = new();
}

public sealed class FaqEntry
{
    public string[] Q { get; init; } = Array.Empty<string>();
    public string[] A { get; init; } = Array.Empty<string>();
}
