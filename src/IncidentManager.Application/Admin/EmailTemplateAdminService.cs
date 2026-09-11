using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>One template's admin view: its metadata + tokens, defaults, current overrides and effective values.</summary>
public sealed record EmailTemplateView(
    string Id, string Title, string Description,
    IReadOnlyList<EmailToken> Tokens,
    string DefaultSubject, string DefaultBody,
    string EffectiveSubject, string EffectiveBody,
    bool IsOverridden, string? CtaLabel);

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
            t.CtaLabel);
    }

    /// <summary>Saves a template's subject + body. A value equal to the default is stored as no override. Audited.</summary>
    public async Task SaveAsync(string id, string subject, string body, CancellationToken ct = default)
    {
        var def = EmailTemplateCatalog.ById(id) ?? throw new InvalidOperationException($"'{id}' is not a known email template.");
        subject = (subject ?? "").Trim();
        body = (body ?? "").Trim();
        if (subject.Length == 0) throw new ArgumentException("Subject must not be empty.");
        if (subject.Length > MaxSubjectLength) throw new ArgumentException($"Subject must be {MaxSubjectLength} characters or fewer.");
        if (body.Length > MaxBodyLength) throw new ArgumentException($"Body must be {MaxBodyLength} characters or fewer.");

        using var db = _factory.CreateDbContext();
        await UpsertOrClearAsync(db, EmailTemplateCatalog.SubjectKey(def.Id), subject, def.DefaultSubject, ct);
        await UpsertOrClearAsync(db, EmailTemplateCatalog.BodyKey(def.Id), body, def.DefaultBodyHtml, ct);
        await db.SaveChangesAsync(ct);
        _reloader.Reload();
    }

    /// <summary>Removes both overrides so the template reverts to its built-in default. Audited; no-op if unset.</summary>
    public async Task ResetAsync(string id, CancellationToken ct = default)
    {
        var def = EmailTemplateCatalog.ById(id) ?? throw new InvalidOperationException($"'{id}' is not a known email template.");
        using var db = _factory.CreateDbContext();
        var rows = await db.AppSettings
            .Where(s => s.Key == EmailTemplateCatalog.SubjectKey(def.Id) || s.Key == EmailTemplateCatalog.BodyKey(def.Id))
            .ToListAsync(ct);
        if (rows.Count == 0) return;
        db.AppSettings.RemoveRange(rows);
        await db.SaveChangesAsync(ct);
        _reloader.Reload();
    }

    // Stores the value, unless it equals the built-in default (then any existing override row is removed).
    private async Task UpsertOrClearAsync(IAppDbContext db, string key, string value, string defaultValue, CancellationToken ct)
    {
        var existing = await db.AppSettings.FirstOrDefaultAsync(s => s.Key == key, ct);
        if (string.Equals(value, defaultValue, StringComparison.Ordinal))
        {
            if (existing is not null) db.AppSettings.Remove(existing);
            return;
        }
        if (existing is null)
        {
            db.AppSettings.Add(new AppSetting { Key = key, Value = value, UpdatedAtUtc = _clock.UtcNow, UpdatedBy = _user.UserId });
        }
        else
        {
            existing.Value = value;
            existing.UpdatedAtUtc = _clock.UtcNow;
            existing.UpdatedBy = _user.UserId;
        }
    }
}
