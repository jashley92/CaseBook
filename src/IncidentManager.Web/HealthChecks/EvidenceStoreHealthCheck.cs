using IncidentManager.Infrastructure.Storage;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.HealthChecks;

/// <summary>
/// Readiness probe for the evidence store (H-09). Confirms the configured root directory is present and
/// reachable — the common failure is an unmounted or disconnected data volume, which <see
/// cref="Directory.Exists(string)"/> reports as absent. Fast, touches no evidence bytes, and returns
/// status only; the resolved path is logged for operators but never returned to the anonymous caller.
/// </summary>
public sealed class EvidenceStoreHealthCheck(IOptions<EvidenceStoreOptions> options) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var root = Path.GetFullPath(options.Value.RootPath);
            return Task.FromResult(Directory.Exists(root)
                ? HealthCheckResult.Healthy()
                : HealthCheckResult.Unhealthy($"Evidence store root is not reachable ({root})."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Evidence store reachability check failed.", ex));
        }
    }
}
