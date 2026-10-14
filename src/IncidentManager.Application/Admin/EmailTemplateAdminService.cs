using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>One template's admin view: its metadata + tokens, defaults, current overrides and effective values.</summary>
public sealed record EmailTemplateView(
    string Id, string Title, string Description,
    IReadOnlyList<EmailToken> Tokens,
    string DefaultSubject, string DefaultBody,
    string EffectiveSubject, string EffectiveBody,
    bool IsOverridden, string? CtaLabel, string Stamp = "");

/// <summary>
/// Reads and writes the admin-editable email templates (E-03b). Overrides are stored as
/// <c>EmailTemplate:{id}:{Subject|Body}</c> rows in the same audited settings table as operational settings
/// and taxonomy labels, so each edit is attributable and hash-chained. A value equal to the built-in default
/// is removed rather than stored (so reset = revert to code default). A write reloads configuration so the
/// composer picks up the change at runtime with no restart. Mirrors <see cref="TaxonomyAdminService"/>.
/// </summary>
public sealed class EmailTemplateAdminService
{
    private const int MaxSubjectLength = 200;
    private const int MaxBodyLength = 20_000;

    private readonly IAppDbContextFactory _factory;
    private readonly IClock _clock;
    private readonly ICurrentUser _user;
    private readonly ISettingsReloader _reloader;

    public EmailTemplateAdminService(IAppDbContextFactory factory, IClock clock, ICurrentUser user, ISettingsReloader reloader)
    {
        _factory = factory;
        _clock = clock;
        _user = user;
        _reloader = reloader;
    }

    public async Task<IReadOnlyList<EmailTemplateView>> GetAllAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var overrides = await db.AppSettings.AsNoTracking()
            .Where(s => s.Key.StartsWith(EmailTemplateCatalog.KeyPrefix))
            .ToDictionaryAsync(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase, ct);

        return EmailTemplateCatalog.Templates.Select(t => View(t, overrides)).ToList();
    }

    public async Task<EmailTemplateView> GetAsync(string id, CancellationToken ct = default)
    {
        var def = EmailTemplateCatalog.ById(id) ?? throw new InvalidOperationException($"'{id}' is not a known email template.");
        using var db = _factory.CreateDbContext();
        var overrides = await db.AppSettings.AsNoTracking()
            .Where(s => s.Key == EmailTemplateCatalog.SubjectKey(def.Id) || s.Key == EmailTemplateCatalog.BodyKey(def.Id))
            .ToDictionaryAsync(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase, ct);
        return View(def, overrides);
    }

    private static EmailTemplateView View(EmailTemplateDefinition t, IReadOnlyDictionary<string, string?> overrides)
    {
        overrides.TryGetValue(EmailTemplateCatalog.SubjectKey(t.Id), out var subjOv);
        overrides.TryGetValue(EmailTemplateCatalog.BodyKey(t.Id), out var bodyOv);
        var subj = string.IsNullOrWhiteSpace(subjOv) ? null : subjOv;
        var body = string.IsNullOrWhiteSpace(bodyOv) ? null : bodyOv;
        return new EmailTemplateView(
            t.Id, t.Title, t.Description, t.Tokens,
            t.DefaultSubject, t.DefaultBodyHtml,
            subj ?? t.DefaultSubject, body ?? t.DefaultBodyHtml,
            IsOverridden: subj is not null || body is not null,
            t.CtaLabel, StampOf(subjOv, bodyOv));
    }

    // BUG-396: the stored overrides the editor opened with (a hash: a body can be 20,000 characters).
    private static string StampOf(string? subject, string? body) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes((subject ?? "") + "" + (body ?? ""))));

    /// <summary>Saves a template's subject + body. A value equal to the default is stored as no override. Audited.
    /// REV-27 / BUG-396: <paramref name="expectedStamp"/> is the template's <see cref="EmailTemplateView.Stamp"/> when the
    /// editor opened; the save writes the whole template, so one someone changed since is refused. Null skips the check
    /// (a config import).</summary>
    public async Task SaveAsync(string id, string subject, string body, string? expectedStamp = null, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<EmailTemplateAdminService>(_user);
        var def = EmailTemplateCatalog.ById(id) ?? throw new InvalidOperationException($"'{id}' is not a known email template.");
        subject = (subject ?? "").Trim();
        body = (body ?? "").Trim();
        if (subject.Length == 0) throw new ArgumentException("Enter a subject.");
        if (subject.Length > MaxSubjectLength) throw new ArgumentException($"Subject must be {MaxSubjectLength} characters or fewer.");
        if (body.Length > MaxBodyLength) throw new ArgumentException($"Body must be {MaxBodyLength} characters or fewer.");

        using var db = _factory.CreateDbContext();
        var subjectKey = EmailTemplateCatalog.SubjectKey(def.Id);
        var bodyKey = EmailTemplateCatalog.BodyKey(def.Id);
        var rows = await db.AppSettings.Where(s => s.Key == subjectKey || s.Key == bodyKey).ToListAsync(ct);
        AppSetting? Row(string key) => rows.FirstOrDefault(r => string.Equals(r.Key, key, StringComparison.OrdinalIgnoreCase));
        if (expectedStamp is not null && !string.Equals(StampOf(Row(subjectKey)?.Value, Row(bodyKey)?.Value), expectedStamp, StringComparison.Ordinal))
            throw new InvalidOperationException($"Someone changed the email template \"{def.Title}\" since you opened it, so nothing was saved: " +
                "it would have undone that. Reload the page, then make your change again.");

        var added = UpsertOrClear(db, Row(subjectKey), subjectKey, subject, def.DefaultSubject)
                    | UpsertOrClear(db, Row(bodyKey), bodyKey, body, def.DefaultBodyHtml);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException ex) when (added)
        {
            // BUG-393: another administrator's first override of this template was saved between the read above and this
            // insert (the unique index refused it).
            using var recheck = _factory.CreateDbContext();
            if (await recheck.AppSettings.AnyAsync(s => s.Key == subjectKey || s.Key == bodyKey, ct))
                throw new InvalidOperationException($"Another administrator saved the email template \"{def.Title}\" at the same moment, " +
                    "so nothing was saved. Reload the page to see their change, then make yours again.", ex);
            throw;
        }
        _reloader.ReloadOrThrow();   // BUG-270
    }

    /// <summary>Removes both overrides so the template reverts to its built-in default. Audited; no-op if unset.</summary>
    public async Task ResetAsync(string id, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<EmailTemplateAdminService>(_user);
        var def = EmailTemplateCatalog.ById(id) ?? throw new InvalidOperationException($"'{id}' is not a known email template.");
        using var db = _factory.CreateDbContext();
        var rows = await db.AppSettings
            .Where(s => s.Key == EmailTemplateCatalog.SubjectKey(def.Id) || s.Key == EmailTemplateCatalog.BodyKey(def.Id))
            .ToListAsync(ct);
        if (rows.Count == 0) return;
        db.AppSettings.RemoveRange(rows);
        await db.SaveChangesAsync(ct);
        _reloader.ReloadOrThrow();   // BUG-270
    }

    // Stores the value, unless it equals the built-in default (then any existing override row is removed). True when a
    // row was added.
    private bool UpsertOrClear(IAppDbContext db, AppSetting? existing, string key, string value, string defaultValue)
    {
        if (string.Equals(value, defaultValue, StringComparison.Ordinal))
        {
            if (existing is not null) db.AppSettings.Remove(existing);
            return false;
        }
        if (existing is null)
        {
            db.AppSettings.Add(new AppSetting { Key = key, Value = value, UpdatedAtUtc = _clock.UtcNow, UpdatedBy = _user.UserId });
            return true;
        }
        existing.Value = value;
        existing.UpdatedAtUtc = _clock.UtcNow;
        existing.UpdatedBy = _user.UserId;
        return false;
    }
}
