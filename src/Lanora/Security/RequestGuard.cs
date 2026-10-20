using Lanora.Api;
using Microsoft.AspNetCore.Http;

namespace Lanora.Security;

/// <summary>
/// SEC03: Canonical Host/port, Origin and Fetch Metadata checks; no CORS; mutations require JSON and a token.
/// Also adds CSP, frame blocking and Referrer-Policy: no-referrer headers.
/// </summary>
public sealed class RequestGuard
{
    private const string Csp =
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
        "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    private readonly RequestDelegate _next;
    private readonly SessionManager _sessions;
    private readonly Func<int> _port;
    private readonly BootstrapThrottle _throttle = new();

    public RequestGuard(RequestDelegate next, SessionManager sessions, Func<int> port)
    {
        _next = next;
        _sessions = sessions;
        _port = port;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        var h = ctx.Response.Headers;
        h["Content-Security-Policy"] = Csp;
        h["X-Frame-Options"] = "DENY";
        h["Referrer-Policy"] = "no-referrer";
        h["X-Content-Type-Options"] = "nosniff";
        h["Cross-Origin-Opener-Policy"] = "same-origin";
        h["Cross-Origin-Resource-Policy"] = "same-origin";
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";

        var expectedHost = $"127.0.0.1:{_port()}";
        var expectedOrigin = $"http://{expectedHost}";

        // DNS rebinding: only the canonical Host is accepted. The host name is case-insensitive.
        if (!string.Equals(ctx.Request.Host.Value, expectedHost, StringComparison.OrdinalIgnoreCase))
        {
            await ApiResults.Write(ctx, 400, "HOST_INVALID");
            return;
        }

        // Cross-origin requests are rejected (no CORS). Scheme/host are compared case-insensitively.
        if (ctx.Request.Headers.TryGetValue("Origin", out var origin) && origin.Count > 0 &&
            !string.Equals(origin.ToString(), expectedOrigin, StringComparison.OrdinalIgnoreCase))
        {
            await ApiResults.Write(ctx, 403, "ORIGIN_REJECTED");
            return;
        }

        if (ctx.Request.Headers.TryGetValue("Sec-Fetch-Site", out var site) && site.Count > 0)
        {
            var v = site.ToString();
            if (v != "same-origin" && v != "none")
            {
                await ApiResults.Write(ctx, 403, "FETCH_SITE_REJECTED");
                return;
            }
        }

        // ASP.NET Core routing is case-insensitive, so the check must be case-insensitive too;
        // otherwise variants such as /API/v1/... would bypass the session check and reach the endpoint.
        var path = ctx.Request.Path.Value ?? "/";
        if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
        {
            h["Cache-Control"] = "no-store";

            // The API is never loaded as a navigated document or inside an iframe.
            if (ctx.Request.Headers.TryGetValue("Sec-Fetch-Dest", out var dest) && dest.Count > 0 &&
                dest.ToString() is "document" or "iframe" or "frame" or "embed" or "object")
            {
                await ApiResults.Write(ctx, 403, "FETCH_DEST_REJECTED");
                return;
            }

            var method = ctx.Request.Method;
            var mutation = !HttpMethods.IsGet(method) && !HttpMethods.IsHead(method);
            if (mutation && !IsJson(ctx.Request.ContentType))
            {
                await ApiResults.Write(ctx, 415, "JSON_REQUIRED");
                return;
            }
            if (HttpMethods.IsOptions(method))
            {
                await ApiResults.Write(ctx, 405, "METHOD_NOT_ALLOWED");
                return;
            }

            if (string.Equals(path, "/api/v1/session/bootstrap", StringComparison.OrdinalIgnoreCase))
            {
                if (!_throttle.Allow())
                {
                    await ApiResults.Write(ctx, 429, "RATE_LIMITED");
                    return;
                }
            }
            else
            {
                var auth = ctx.Request.Headers.Authorization.ToString();
                var token = auth.StartsWith("Bearer ", StringComparison.Ordinal) ? auth[7..].Trim() : null;
                if (!_sessions.Validate(token))
                {
                    await ApiResults.Write(ctx, 401, "SESSION_INVALID");
                    return;
                }
            }
        }
        else if (!HttpMethods.IsGet(ctx.Request.Method) && !HttpMethods.IsHead(ctx.Request.Method))
        {
            await ApiResults.Write(ctx, 405, "METHOD_NOT_ALLOWED");
            return;
        }

        await _next(ctx);
    }

    private static bool IsJson(string? contentType) =>
        contentType is not null && contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase);

    /// <summary>Limits brute-force attempts on the launch endpoint.</summary>
    private sealed class BootstrapThrottle
    {
        private readonly Queue<DateTimeOffset> _hits = new();
        private readonly object _gate = new();

        public bool Allow()
        {
            lock (_gate)
            {
                var now = DateTimeOffset.UtcNow;
                while (_hits.Count > 0 && now - _hits.Peek() > TimeSpan.FromMinutes(1)) _hits.Dequeue();
                if (_hits.Count >= 20) return false;
                _hits.Enqueue(now);
                return true;
            }
        }
    }
}
