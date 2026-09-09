namespace IncidentManager.Web.Security;

/// <summary>Adds hardening response headers to every response.</summary>
public sealed class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

    public async Task Invoke(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";
        // Disable powerful features the app never uses (S-07 hardening).
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
        headers["Content-Security-Policy"] =
            "default-src 'self'; " +
            "img-src 'self' data:; " +
            // 'unsafe-inline' is required for the app's inline style attributes (e.g. tactic-colour vars)
            // and Blazor's injected styles; script has no such allowance (script-src 'self' only).
            "style-src 'self' 'unsafe-inline'; " +
            "script-src 'self'; " +
            "object-src 'none'; " +
            // 'self' covers the same-origin SignalR WebSocket upgrade the Blazor Server circuit uses
            // (S-07: was 'ws: wss:', which allowed a socket to any host).
            "connect-src 'self'; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self'";
        headers.Remove("Server");

        await _next(context);
    }
}
