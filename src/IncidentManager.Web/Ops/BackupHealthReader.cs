using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Ops;

namespace IncidentManager.Web.Ops;

/// <summary>
/// Reads the out-of-band backup/restore status file and evaluates its freshness for the Admin
/// Diagnostics panel (H-04). The app only ever <em>reads</em> this file — SQL Agent / the
/// restore-verification job writes it (see docs/OPERATIONS.md §1.3) — so the signal is available
/// even while the database is unavailable. Reading is decoupled from the audit chain by design.
/// </summary>
public sealed class BackupHealthReader
{
    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;
    private readonly IClock _clock;

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public BackupHealthReader(IConfiguration config, IWebHostEnvironment env, IClock clock)
    {
        _config = config;
        _env = env;
        _clock = clock;
    }

    public BackupHealthReport Read()
    {
        var path = _config["BackupStatus:FilePath"];
        var backupMaxAge = TimeSpan.FromHours(_config.GetValue("BackupStatus:BackupMaxAgeHours", 24.0));
        var restoreMaxAge = TimeSpan.FromDays(_config.GetValue("BackupStatus:RestoreMaxAgeDays", 35.0));

        if (string.IsNullOrWhiteSpace(path))
            return BackupHealthEvaluator.Evaluate(
                null, _clock.UtcNow, backupMaxAge, restoreMaxAge, "(not configured)", configured: false);

        var full = Path.IsPathRooted(path) ? path : Path.Combine(_env.ContentRootPath, path);

        BackupStatusFile? status = null;
        if (File.Exists(full))
        {
            try
            {
                status = JsonSerializer.Deserialize<BackupStatusFile>(File.ReadAllText(full), JsonOptions);
            }
            catch
            {
                status = null; // present but unreadable/malformed → Missing verdict
            }
        }

        return BackupHealthEvaluator.Evaluate(status, _clock.UtcNow, backupMaxAge, restoreMaxAge, full, configured: true);
    }
}
