using IncidentManager.Infrastructure.Storage;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.HealthChecks;

/// <summary>
/// Readiness probe for the evidence store (H-09). Confirms the configured root directory is present and
/// reachable — the common failure is an unmounted or disconnected data volume, which <see
/// cref="Directory.Exists(string)"/> reports as absent. Fast, touches no evidence bytes, and returns
/// status only; the resolved path is logged for operators but never returned to the anonymous caller.
/// PROD-56 (C10): on a UNC share whose server is down, Directory.Exists can block for a long time, and load balancers
/// poll this often; past <see cref="TimeLimit"/> the store counts as unreachable and the probe answers.
/// </summary>
public sealed class EvidenceStoreHealthCheck(IOptions<EvidenceStoreOptions> options) : IHealthCheck
{
    /// <summary>How long the check may wait for the store's folder to answer.</summary>
    public TimeSpan TimeLimit { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Whether the folder is there (replaceable in tests, to stand in for a share that doesn't answer).</summary>
    public Func<string, bool> Exists { get; init; } = Directory.Exists;

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var root = Path.GetFullPath(options.Value.RootPath);
            return await Task.Run(() => Exists(root), cancellationToken).WaitAsync(TimeLimit, cancellationToken)
                ? HealthCheckResult.Healthy()
                : HealthCheckResult.Unhealthy($"Evidence store root is not reachable ({root}).");
        }
        catch (TimeoutException)
        {
            return HealthCheckResult.Unhealthy($"Evidence store root didn't answer within {TimeLimit.TotalSeconds:0} seconds.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return HealthCheckResult.Unhealthy("Evidence store reachability check failed.", ex);
        }
    }
}
