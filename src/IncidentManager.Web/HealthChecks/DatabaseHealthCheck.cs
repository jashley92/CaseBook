using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace IncidentManager.Web.HealthChecks;

/// <summary>
/// Readiness probe for database connectivity (H-09). Opens a short-lived context and asks the provider
/// whether it can reach the database — a cheap round-trip that touches no case data. Reports status only
/// (Healthy/Unhealthy); the exception text is logged for operators but never returned to the caller, so
/// the anonymous <c>/health</c> endpoint leaks no connection or schema detail.
/// </summary>
public sealed class DatabaseHealthCheck(IDbContextFactory<AppDbContext> factory) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var db = await factory.CreateDbContextAsync(cancellationToken);
            return await db.Database.CanConnectAsync(cancellationToken)
                ? HealthCheckResult.Healthy()
                : HealthCheckResult.Unhealthy("Database is not reachable.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database connectivity check failed.", ex);
        }
    }
}
