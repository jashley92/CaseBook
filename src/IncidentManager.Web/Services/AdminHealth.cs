using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Common;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Notifications;
using IncidentManager.Application.Ops;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Web.Notifications;
using IncidentManager.Web.Ops;
using IncidentManager.Web.Secrets;
using IncidentManager.Web.Updates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Services;

/// <summary>How much something found needs an administrator: something broken, something to see to, or worth knowing.</summary>
public enum AttentionLevel
{
    Problem,
    Warning,
    Notice,
}

/// <summary>One check on Diagnostics: its result, what it found, and where to fix it.</summary>
public sealed record HealthCheck(string Label, bool Ok, string Detail, string? FixHref = null, AttentionLevel Level = AttentionLevel.Problem);

/// <summary>Something an administrator should see to, with a link to where it's fixed.</summary>
public sealed record AttentionItem(AttentionLevel Level, string Title, string Detail, string FixHref, string FixLabel);

/// <summary>A first-run step on the Administration overview, done or not, with where it's done.</summary>
public sealed record SetupStep(string Title, bool Done, string Detail, string Href);

/// <summary>
/// What's wrong with this CaseBook and where to fix it, read when an Administration page opens: the health checks
/// Diagnostics lists, and the "Needs attention" summary the overview and Diagnostics both show (every problem the checks,
/// deliveries, scheduled jobs, backups, keys and integrity checks found, worst first). One place, so the two pages never
/// disagree. Reads in-memory status and a few quick queries; nothing is changed.
/// </summary>
public sealed class AdminHealth(
    IDbContextFactory<AppDbContext> dbFactory,
    IEvidenceStore evidenceStore,
    IConfiguration config,
    IWebHostEnvironment env,
    ISealSigner signer,
    IOptionsMonitor<EmailOptions> emailOptions,
    SmtpSignInStore smtpSignIns,
    StoredSecretAdminService storedSecretAdmin,
    StoredSecretStore storedSecrets,
    RetentionReviewState retentionCount,
    AccessReviewService accessReviews,
    IDeliveryHealth delivery,
    IJobStatus jobs,
    BackupHealthReader backup,
    IEvidenceKeyring evidenceKey,
    IEvidenceIntegrityMonitor evidenceIntegrity,
    IntegrityCheckState integrityCheck,
    ISecretResolutionHealth secretHealth,
    SealCopyStatus sealCopies,
    IChatNotifier chat,
    UpdateCheckService updates,
    IClock clock)
{
    // Where each kind of problem is fixed.
    public const string Diagnostics = "admin/settings/diagnostics";
    public const string DeliveryAnchor = Diagnostics + "#diag-delivery";
    public const string JobsAnchor = Diagnostics + "#diag-jobs";
    public const string BackupAnchor = Diagnostics + "#diag-backup";
    public const string EvidenceKeyAnchor = Diagnostics + "#diag-evidence-key";
    public const string KeysAnchor = Diagnostics + "#diag-keys";
    public const string SecretsAnchor = Diagnostics + "#diag-secrets";

    /// <summary>A setting's page, scrolled to it (the control's id is its key).</summary>
    public static string SettingHref(string key) => AdminSearchIndex.SettingHref(key);

    /// <summary>When the last <see cref="CheckAsync"/> read everything.</summary>
    public DateTimeOffset? CheckedAtUtc { get; private set; }

    public async Task<IReadOnlyList<HealthCheck>> CheckAsync(CancellationToken ct = default)
    {
        var checks = new List<HealthCheck>();

        bool dbOk;
        IReadOnlyList<string> pending = [];
        await using (var db = await dbFactory.CreateDbContextAsync(ct))
        {
            try { dbOk = await db.Database.CanConnectAsync(ct); } catch (Exception ex) when (ex is not OperationCanceledException) { dbOk = false; }
            checks.Add(new HealthCheck("Database connectivity", dbOk, dbOk ? db.Database.ProviderName ?? "" : "cannot connect", "admin/settings/server"));
            if (dbOk)
            {
                try { pending = (await db.Database.GetPendingMigrationsAsync(ct)).ToList(); }
                catch (Exception ex) when (ex is not OperationCanceledException) { pending = []; }
            }
        }

        // PROD-56: the store's own probe, in time (a share that's down answers rather than hangs the page) and never
        // recreating a store that held evidence and has vanished (this check used to, just by being looked at).
        var storeProblem = await evidenceStore.ProbeAsync(ct);
        checks.Add(new HealthCheck("Evidence store writable", storeProblem is null, storeProblem ?? evidenceStore.Location, "admin/settings/evidence"));
        checks.Add(WritableCheck("Report output writable", config["ReportOutput:RootPath"]));
        // The app doesn't start without its signing key, so one is always loaded; say which (a file, a certificate or
        // CyberArk). This checked for the PEM file, so a key in the certificate store read as missing.
        checks.Add(new HealthCheck("Seal signing key", true, $"{signer.KeyId} · {signer.KeySource}"));

        // A value saved before today's limits (or set in appsettings) blocks saving its section until corrected.
        var invalid = SettingsCatalog.FindInvalid(key => AdminSettingsDisplay.ConfiguredValue(config, key));
        checks.Add(new HealthCheck("Settings within limits", invalid.Count == 0, invalid.Count == 0
                ? "every setting passes its rules"
                : string.Join(" ", invalid.Select(i => $"{i.Problem} It's currently {i.Value}.")),
            invalid.Count == 0 ? null : SettingHref(invalid[0].Definition.Key), AttentionLevel.Warning));

        // CAP-05: a relay sign-in that can't be used stops every email; a plain-text password is said too.
        var mail = emailOptions.CurrentValue;
        if (SmtpSignIn.InServerConfig(mail))
        {
            var problem = SmtpSignIn.Problem(mail);
            var warnings = SmtpSignIn.Warnings(mail);
            checks.Add(new HealthCheck("Email relay sign-in", problem is null && warnings.Count == 0,
                problem ?? (warnings.Count > 0 ? string.Join(" ", warnings) : SmtpSignIn.Describe(mail)),
                "admin/settings/server", problem is null ? AttentionLevel.Warning : AttentionLevel.Problem));
        }
        else if (await smtpSignIns.StatusAsync(ct: ct) is { } saved)
        {
            checks.Add(new HealthCheck("Email relay sign-in", !saved.PasswordUnreadable, saved.PasswordUnreadable
                ? "The SMTP password saved in Administration can't be decrypted on this server: re-enter it (Notifications, Email sign-in)."
                : saved.Mode == SmtpSignInMode.None ? "none (the relay takes mail without a sign-in)" : "set in Administration",
                "admin/settings/notifications#email-sign-in"));
        }
        // CAP-40: a secret saved in Administration that can't be decrypted here stops its sends: re-enter it.
        foreach (var d in StoredSecretDefinition.All)
        {
            if (storedSecretAdmin.SetInServerConfiguration(d.Kind)) continue;
            var saved = await storedSecrets.StatusAsync(d.Kind, ct: ct);
            if (!saved.Set) continue;
            checks.Add(new HealthCheck(char.ToUpperInvariant(d.Label[0]) + d.Label[1..], !saved.Unreadable, saved.Unreadable
                    ? $"The {d.Label} saved in Administration can't be decrypted on this server: re-enter the {d.Label} ({d.Where})."
                    : "saved in Administration",
                d.Kind == StoredSecretKind.ChatWebhookUrl ? "admin/settings/notifications#chat-webhook" : "admin/settings/integrations#siem-token"));
        }
        checks.Add(new HealthCheck("Schema up to date", dbOk && pending.Count == 0,
            !dbOk ? "can't tell: the database isn't answering" : pending.Count > 0 ? $"{pending.Count} pending" : "no pending migrations",
            Diagnostics, AttentionLevel.Warning));

        // CAP-10: the nightly retention count (every case but exercises). A reminder only: the review archives nothing itself.
        checks.Add(retentionCount.Last switch
        {
            null => new HealthCheck("Retention review", true, "not counted yet (it's counted within minutes of start-up, then daily)"),
            { Years: 0 } => new HealthCheck("Retention review", true, "off (case retention is 0 years)"),
            { Due: 0 } c => new HealthCheck("Retention review", true,
                $"no closed case is past {Plural.Of(c.Years, "year")} · counted {c.CountedAtUtc:u}"),
            var c => new HealthCheck("Retention review", false,
                $"{Plural.Of(c.Due, "closed case")} past {Plural.Of(c.Years, "year")} waiting for review ({c.UnderHold:N0} under a legal hold), " +
                $"counted {c.CountedAtUtc:u}.", "admin/settings/retention#retention-review", AttentionLevel.Warning),
        });
        // CAP-15: the periodic access review, recorded under Roles & access, reminded as the evidence-key drill is.
        var lastReview = await accessReviews.GetLastReviewAsync(ct);
        var reminder = AccessReviewService.ReminderFor(lastReview, accessReviews.ReminderDays, clock.UtcNow);
        checks.Add(new HealthCheck("Access review", !reminder.Due, reminder switch
        {
            { Off: true } => "reminder off" + (lastReview is { } l0 ? $" · last recorded {Day(l0.AtUtc)} by {l0.Reviewer}" : ""),
            _ when lastReview is null => "No access review has been recorded. Review Roles & access and record it there.",
            { Due: true } => $"Last recorded {Day(lastReview.AtUtc)} by {lastReview.Reviewer}, more than {Plural.Of(accessReviews.ReminderDays, "day")} ago: " +
                             "review Roles & access and record it there.",
            _ => $"last recorded {Day(lastReview.AtUtc)} by {lastReview.Reviewer} · next due {Day(reminder.DueAtUtc)}",
        }, "admin/roles#ar-record-title", AttentionLevel.Warning));

        CheckedAtUtc = clock.UtcNow;
        return checks;
    }

    /// <summary>
    /// Everything that needs an administrator, worst first: each failed check, and what the deliveries, jobs, backups,
    /// keys and integrity checks found. Pass the checks from <see cref="CheckAsync"/> when the page has them already.
    /// </summary>
    public async Task<IReadOnlyList<AttentionItem>> AttentionAsync(IReadOnlyList<HealthCheck>? checks = null, CancellationToken ct = default)
    {
        checks ??= await CheckAsync(ct);
        var items = checks.Where(c => !c.Ok)
            .Select(c => new AttentionItem(c.Level, c.Label, c.Detail, c.FixHref ?? Diagnostics, c.FixHref is null ? "Diagnostics" : "Fix it"))
            .ToList();
        var now = clock.UtcNow;

        // Email that's on but can't be sent.
        if (config.GetValue<bool>("Email:Enabled") && string.IsNullOrWhiteSpace(config["Email:From"]))
            items.Add(new(AttentionLevel.Problem, "Email has no From address", "Email is on, but sends fail without a From address.",
                SettingHref("Email:From"), "Set it"));

        // Deliveries failing now.
        foreach (var (name, s) in delivery.Snapshot())
        {
            if (!s.LastAttemptFailed && !s.BackedOff(now)) continue;
            items.Add(new(AttentionLevel.Warning, $"{ChannelLabel(name)} is failing",
                s.BackedOff(now) ? $"Paused after repeated failures until {s.BackedOffUntilUtc:u}. Last error: {s.LastFailure}" : $"Last error: {s.LastFailure}",
                DeliveryAnchor, "Delivery health"));
        }
        if (chat.StoppedReason is { } chatStopped)
            items.Add(new(AttentionLevel.Warning, "Team chat is stopped", chatStopped, DeliveryAnchor, "Delivery health"));
        var held = await HeldEmailSummary.ReadAsync(dbFactory, HeldEmailSummary.DefaultLimit, ct);
        if (held.Count > 0)
            items.Add(new(AttentionLevel.Warning, $"{Plural.Of(held.Count, "email")} held for the relay",
                $"Waiting since {held.OldestUtc:u}; they're sent when the relay takes mail again.", DeliveryAnchor, "Delivery health"));

        // Scheduled jobs whose last run failed.
        foreach (var j in jobs.Snapshot().Where(j => j.Outcome == JobOutcome.Failed))
            items.Add(new(AttentionLevel.Warning, $"{j.Job.Name} failed", $"Last run {j.FinishedAtUtc:u}: {j.LastErrorType}.", JobsAnchor, "Scheduled jobs"));

        // Backups.
        var b = backup.Read();
        if (b.Overall is BackupHealthState.Failed or BackupHealthState.Missing or BackupHealthState.Stale)
            items.Add(new(b.Overall == BackupHealthState.Stale ? AttentionLevel.Warning : AttentionLevel.Problem,
                b.Overall switch
                {
                    BackupHealthState.Failed => b.Items.Any(i => i.State == BackupHealthState.Failed && i.Label.Contains("backup", StringComparison.OrdinalIgnoreCase))
                        ? "The latest backup failed" : "The latest restore drill failed",
                    BackupHealthState.Missing => "No backup recorded",
                    _ => "Backups are out of date",
                },
                string.Join(" ", b.Items.Where(i => i.State is BackupHealthState.Failed or BackupHealthState.Missing or BackupHealthState.Stale).Select(i => $"{i.Label}: {i.Detail}.")),
                BackupAnchor, "Backup health"));

        // Evidence encryption.
        switch (evidenceKey.State)
        {
            case EvidenceKeyState.Unavailable:
                items.Add(new(AttentionLevel.Problem, "The evidence key can't be opened",
                    $"Evidence and reports can't be read or stored until it can. {evidenceKey.Problem}", EvidenceKeyAnchor, "Evidence encryption"));
                break;
            case EvidenceKeyState.NeedsBackup:
                items.Add(new(AttentionLevel.Warning, "Evidence encryption is waiting for a backup",
                    "Nothing is encrypted until a recovery certificate or shares exist.", EvidenceKeyAnchor, "Evidence encryption"));
                break;
            case EvidenceKeyState.NotConfigured:
                items.Add(new(AttentionLevel.Warning, "Evidence encryption can't start",
                    evidenceKey.Problem ?? "Nothing is configured to protect its key.", EvidenceKeyAnchor, "Evidence encryption"));
                break;
        }

        // Integrity.
        if (evidenceIntegrity.Current is { IsClean: false } ev)
            items.Add(new(AttentionLevel.Problem, "Stored evidence doesn't match its record",
                $"{Plural.Of(ev.DriftCount, "finding")} in the last check ({ev.CheckedAtUtc:u}).", "admin/settings/integrity", "Evidence-at-rest results"));
        if (integrityCheck.LastCycle is { Intact: false } cycle)
            items.Add(new(AttentionLevel.Problem, "The integrity check found a problem",
                $"The last check ({cycle.FinishedAtUtc:u}) found the audit trail or a record altered.", "integrity", "Integrity & audit"));
        foreach (var copy in sealCopies.Snapshot().Where(c => !c.Ok))
            items.Add(new(AttentionLevel.Warning, $"Seal copy to {copy.Destination} failed", $"{copy.LastError} ({copy.LastAttemptUtc:u})", KeysAnchor, "Seal copies"));
        if (config.GetValue<bool>("Secrets:CyberArk:Enabled") && secretHealth.Current is { LastAttemptFailed: true } sh)
            items.Add(new(AttentionLevel.Problem, "A secret couldn't be fetched from CyberArk",
                $"{sh.LastFailureReference}: {sh.LastFailureReason}", SecretsAnchor, "Secret resolution"));

        // Worth knowing.
        if (updates.UpdateAvailable)
            items.Add(new(AttentionLevel.Notice, updates.Status.Latest is { } r ? $"CaseBook {r.Tag} is available" : "A new CaseBook release is available",
                "See what's in it and how to upgrade.", "admin/settings/updates", "Updates"));

        return [.. items.OrderBy(i => i.Level)];
    }

    /// <summary>The first-run steps on the overview: what a new install still needs, each linking to where it's done.</summary>
    public async Task<IReadOnlyList<SetupStep>> SetupAsync(CancellationToken ct = default)
    {
        var org = config["Reporting:OrganizationName"];
        var lastReview = await accessReviews.GetLastReviewAsync(ct);
        return
        [
            new("Name your organization", !string.IsNullOrWhiteSpace(org) && org != SettingsCatalog.ByKey["Reporting:OrganizationName"].Default,
                "Shown on reports and emails.", SettingHref("Reporting:OrganizationName")),
            new("Turn on email", config.GetValue<bool>("Email:Enabled") && !string.IsNullOrWhiteSpace(config["Email:From"]),
                "Notifications are logged, not sent, until email is on with a From address.", SettingHref("Email:Enabled")),
            new("Set this server's address", !string.IsNullOrWhiteSpace(config["App:BaseUrl"]),
                "So emails and chat posts link back to CaseBook.", SettingHref("App:BaseUrl")),
            new("Report backup status", backup.Read().Overall != BackupHealthState.NotConfigured,
                "Set BackupStatus:FilePath, then schedule deploy\\Backup-CaseBook.ps1 (or, with a backup product, Update-CaseBookBackupStatus.ps1) " +
                "and the monthly Test-CaseBookRestore.ps1 drill (OPERATIONS.md section 1).", BackupAnchor),
            new("Record an access review", lastReview is not null,
                "Review who holds each role, and record it.", "admin/roles#ar-record-title"),
        ];
    }

    private static string ChannelLabel(string channel) => channel switch
    {
        DeliveryHealth.Smtp => "Email delivery",
        DeliveryHealth.Chat => "Team chat",
        DeliveryHealth.SiemQueue => "The SIEM queue",
        _ when channel.StartsWith("siem:", StringComparison.Ordinal) => $"SIEM {channel["siem:".Length..]}",
        _ => channel,
    };

    // BUG-531: a date in Diagnostics is Gregorian whatever the server culture.
    private static string Day(DateTimeOffset? at) =>
        at?.UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture) ?? "";

    private HealthCheck WritableCheck(string label, string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return new HealthCheck(label, false, "path not configured", "admin/settings/server");
        var full = Path.IsPathRooted(path) ? path : Path.Combine(env.ContentRootPath, path);
        try
        {
            Directory.CreateDirectory(full);
            var probe = Path.Combine(full, $".health-{Guid.NewGuid():N}.tmp");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return new HealthCheck(label, true, full);
        }
        catch (Exception ex)
        {
            return new HealthCheck(label, false, ex.GetType().Name, "admin/settings/server");
        }
    }
}
