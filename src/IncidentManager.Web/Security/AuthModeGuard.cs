using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace IncidentManager.Web.Security;

/// <summary>
/// Decides at startup whether the app authenticates with Windows (Negotiate) or the passwordless
/// <see cref="DevAuthenticationHandler"/>, and refuses to start when the dev handler would run anywhere it
/// shouldn't. The dev handler signs everyone in with the configured roles (all five by default), so a missing
/// or mistyped <c>Auth:Mode</c> must stop startup, not silently make every visitor an administrator.
/// </summary>
public static class AuthModeGuard
{
    /// <summary>Opt-in that lets a non-Production, non-Development environment (a demo or QA box) use dev sign-in.</summary>
    public const string AllowOutsideDevelopmentKey = "Auth:AllowDevSignInOutsideDevelopment";

    /// <summary>
    /// True for Windows authentication, false for dev sign-in. Dev sign-in is allowed only in the Development
    /// environment, or in another non-Production environment that sets <see cref="AllowOutsideDevelopmentKey"/>;
    /// Production always requires <c>Auth:Mode=Windows</c>.
    /// </summary>
    /// <exception cref="InvalidOperationException">Dev sign-in would run outside where it's allowed.</exception>
    public static bool UseWindows(IHostEnvironment env, IConfiguration config)
    {
        var authMode = config["Auth:Mode"] ?? "Dev";
        if (string.Equals(authMode, "Windows", StringComparison.OrdinalIgnoreCase)) return true;

        if (env.IsDevelopment()) return false;

        if (env.IsProduction())
            throw new InvalidOperationException(
                $"Auth:Mode is '{authMode}' in Production. Production requires Auth:Mode=Windows; " +
                "the development authentication handler must never be used outside Development.");

        if (config.GetValue<bool>(AllowOutsideDevelopmentKey)) return false;

        throw new InvalidOperationException(
            $"Auth:Mode is '{authMode}' in the '{env.EnvironmentName}' environment. Set Auth:Mode=Windows, or, for a " +
            $"demo or test server only, set {AllowOutsideDevelopmentKey}=true to sign everyone in with the DevAuth roles.");
    }
}
