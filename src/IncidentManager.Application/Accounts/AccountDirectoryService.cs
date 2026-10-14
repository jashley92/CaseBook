using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Application.Accounts;

/// <summary>
/// BUG-416: an account entity's details from the directory. The details as they were when the account was added are
/// kept with the case (<see cref="CaptureOnAddAsync"/>); an analyst can look the account up again at any time
/// (<see cref="LookupAsync"/>, shown but not kept) and keep that result as a new snapshot (<see cref="SaveAsync"/>).
/// Snapshots are append-only and hashed. Looking up needs ViewCases; keeping a snapshot needs EditCases. Both go
/// through the need-to-know filter.
/// </summary>
public sealed class AccountDirectoryService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly IAccountDirectory _directory;
    private readonly ILogger<AccountDirectoryService>? _log;

    public AccountDirectoryService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, IAccountDirectory directory,
        ILogger<AccountDirectoryService>? log = null)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _directory = directory;
        _log = log;
    }

    /// <summary>How many accounts one add looks up.</summary>
    public const int MaxCapturedPerAdd = 50;

    /// <summary>Whether there is a directory to ask here.</summary>
    public bool IsAvailable => _directory.IsAvailable;

    /// <summary>The entity types that name an account: an account, or an email address that is a UPN.</summary>
    public static bool IsAccountType(EntityType type) => type is EntityType.Account or EntityType.EmailAddress;

    /// <summary>The entity's details from the directory now. Not kept.</summary>
    public async Task<DirectoryLookup> LookupAsync(Guid caseId, Guid entityId, CancellationToken ct = default)
    {
        Require(Permission.ViewCases);
        using var db = _factory.CreateDbContext();
        var entity = await VisibleEntityAsync(db, caseId, entityId, ct);
        if (!_directory.IsAvailable)
            return DirectoryLookup.Unavailable("There's no directory to look accounts up in here.") with { LookedUp = entity.Value };
        return await _directory.LookupAsync(entity.Value, ct) with { LookedUp = entity.Value };   // BUG-432
    }

    /// <summary>
    /// Keeps <paramref name="lookup"/> (what the analyst was shown) as a new snapshot of the entity. A lookup that
    /// couldn't reach the directory, or wasn't made (BUG-419), has nothing to keep. BUG-432: nor has one made for a value
    /// the entity no longer has (it was edited meanwhile).
    /// </summary>
    public async Task<AccountDirectorySnapshot> SaveAsync(Guid caseId, Guid entityId, DirectoryLookup lookup, CancellationToken ct = default)
    {
        Require(Permission.EditCases);
        if (lookup.Outcome == DirectoryLookupOutcome.Unavailable)
            throw new InvalidOperationException("The directory couldn't be reached, so there's nothing to keep. Try the lookup again.");
        if (lookup.Outcome == DirectoryLookupOutcome.NotLookedUp)
            throw new InvalidOperationException("That account wasn't looked up in the directory, so there's nothing to keep.");
        using var db = _factory.CreateDbContext();
        var entity = await VisibleEntityAsync(db, caseId, entityId, ct);
        if (!string.Equals(lookup.LookedUp, entity.Value, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The account was changed since it was looked up. Look it up again.");
        var snapshot = Snapshot(caseId, entity, lookup, DirectorySnapshotTrigger.Requested);
        db.AccountDirectorySnapshots.Add(snapshot);
        await db.SaveChangesAsync(ct);
        return snapshot;
    }

    /// <summary>How long one add (a paste, an import) spends on the directory in all, at most.</summary>
    public static readonly TimeSpan CaptureBudget = TimeSpan.FromSeconds(15);

    /// <summary>
    /// BUG-420: what one add may still spend on the directory: <see cref="MaxCapturedPerAdd"/> lookups within
    /// <see cref="CaptureBudget"/>, shared by every batch of the add. Once the directory is unavailable, the rest of the
    /// add isn't looked up.
    /// </summary>
    public sealed class CaptureAllowance(TimeSpan? budget = null)
    {
        private readonly TimeSpan _budget = budget ?? CaptureBudget;

        internal int Lookups { get; set; } = MaxCapturedPerAdd;
        internal bool Stopped { get; set; }
        // Only time spent waiting on the directory counts: an import's batches spend their own time saving, and a large
        // one would otherwise have used the budget up before its later batches' accounts were asked about.
        internal TimeSpan Spent { get; set; }
        internal TimeSpan Left => _budget - Spent;
    }

    /// <summary>
    /// Takes a snapshot of each account among <paramref name="entityIds"/> that the directory knows, just after the
    /// accounts were added. Best effort: an unreachable directory, or one that doesn't know the account, records
    /// nothing, and the add has already been saved either way.
    /// </summary>
    public Task<int> CaptureOnAddAsync(Guid caseId, IEnumerable<Guid> entityIds, CancellationToken ct = default) =>
        CaptureOnAddAsync(caseId, entityIds, new CaptureAllowance(), ct);

    /// <summary>The same, within what <paramref name="allowance"/> has left (BUG-420).</summary>
    public async Task<int> CaptureOnAddAsync(Guid caseId, IEnumerable<Guid> entityIds, CaptureAllowance allowance,
        CancellationToken ct = default)
    {
        if (!_directory.IsAvailable || !_user.Has(Permission.EditCases) || allowance.Stopped) return 0;
        var ids = entityIds.Distinct().ToList();
        if (ids.Count == 0) return 0;
        try
        {
            using var db = _factory.CreateDbContext();
            if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct)) return 0;
            var entities = await db.CaseEntities.AsNoTracking()
                .Where(e => e.CaseId == caseId && ids.Contains(e.Id))
                .ToListAsync(ct);
            var taken = 0;
            // BUG-420: one after another, within the add's allowance, so a large paste isn't held up by the directory.
            foreach (var e in entities.Where(e => IsAccountType(e.Type)).OrderBy(e => ids.IndexOf(e.Id)))   // in the order added
            {
                var left = allowance.Left;
                if (allowance.Lookups <= 0 || left <= TimeSpan.Zero) { allowance.Stopped = true; break; }
                allowance.Lookups--;
                DirectoryLookup lookup;
                var asked = System.Diagnostics.Stopwatch.GetTimestamp();
                using (var budget = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    budget.CancelAfter(left);
                    try { lookup = await _directory.LookupAsync(e.Value, budget.Token); }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested) { allowance.Stopped = true; break; }
                    finally { allowance.Spent += System.Diagnostics.Stopwatch.GetElapsedTime(asked); }
                }
                // BUG-420: an unavailable directory isn't asked again for the rest of the add.
                if (lookup.Outcome == DirectoryLookupOutcome.Unavailable) { allowance.Stopped = true; break; }
                // An email address is only an account when the directory has it; an account not found is worth keeping
                // (the name didn't resolve when it was added), an unreachable directory isn't. One that wasn't looked up
                // (BUG-419: another organisation's domain) keeps nothing either.
                if (lookup.Outcome == DirectoryLookupOutcome.Found
                    || (lookup.Outcome == DirectoryLookupOutcome.NotFound && e.Type == EntityType.Account))
                {
                    db.AccountDirectorySnapshots.Add(Snapshot(caseId, e, lookup, DirectorySnapshotTrigger.Added));
                    taken++;
                }
            }
            if (taken > 0) await db.SaveChangesAsync(ct);
            return taken;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "Couldn't record the directory details of accounts added to a case.");
            return 0;
        }
    }

    /// <summary>The entity's kept snapshots, newest first.</summary>
    public async Task<IReadOnlyList<AccountDirectorySnapshot>> SnapshotsAsync(Guid caseId, Guid entityId, CancellationToken ct = default)
    {
        Require(Permission.ViewCases);
        using var db = _factory.CreateDbContext();
        if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct)) return [];
        return await db.AccountDirectorySnapshots.AsNoTracking()
            .Where(s => s.CaseId == caseId && s.EntityId == entityId)
            .OrderByDescending(s => s.CreatedAtUtc)
            .ToListAsync(ct);
    }

    /// <summary>
    /// For a value typed without a type that could be a bare sAMAccountName: whether the directory has that account
    /// (so the form can suggest Account). False when there's no directory or it can't be reached.
    /// </summary>
    public async Task<bool> IsKnownAccountAsync(string value, CancellationToken ct = default)
    {
        if (!_directory.IsAvailable || !_user.Has(Permission.ViewCases)) return false;
        var v = value.Trim();
        // A sAMAccountName is at most 20 characters and has no spaces or path characters ("john.doe" is allowed: it also
        // reads as a domain, which is why the directory is asked).
        if (v.Length is 0 or > 20 || v.IndexOfAny([' ', '/', '\\', ':', '@']) >= 0) return false;
        try { return (await _directory.LookupAsync(v, ct)).Outcome == DirectoryLookupOutcome.Found; }
        catch (Exception ex) when (ex is not OperationCanceledException) { return false; }
    }

    private AccountDirectorySnapshot Snapshot(Guid caseId, CaseEntity entity, DirectoryLookup lookup, DirectorySnapshotTrigger trigger)
    {
        var a = lookup.Outcome == DirectoryLookupOutcome.Found ? lookup.Account : null;
        return new AccountDirectorySnapshot
        {
            CaseId = caseId, EntityId = entity.Id, LookedUp = Cap(entity.Value, 400)!, Trigger = trigger, Found = a is not null,
            SamAccountName = Cap(a?.SamAccountName, 256), UserPrincipalName = Cap(a?.UserPrincipalName, 400),
            DisplayName = Cap(a?.DisplayName, 400), Title = Cap(a?.Title, 400), Department = Cap(a?.Department, 400),
            Manager = Cap(a?.Manager, 400), Email = Cap(a?.Email, 400), DistinguishedName = Cap(a?.DistinguishedName, 1000),
            Enabled = a?.Enabled, LockedOut = a?.LockedOut, AccountExpiresUtc = a?.AccountExpiresUtc,
            LastLogonUtc = a?.LastLogonUtc, PasswordLastSetUtc = a?.PasswordLastSetUtc, WhenCreatedUtc = a?.WhenCreatedUtc,
            CreatedBy = _user.UserId, CreatedAtUtc = _clock.UtcNow
        };
    }

    private static string? Cap(string? s, int max) => s is null ? null : s.Length > max ? s[..max] : s;

    private async Task<CaseEntity> VisibleEntityAsync(IAppDbContext db, Guid caseId, Guid entityId, CancellationToken ct)
    {
        if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct))
            throw new InvalidOperationException("Case not found or not accessible.");
        var entity = await db.CaseEntities.AsNoTracking().FirstOrDefaultAsync(e => e.CaseId == caseId && e.Id == entityId, ct)
            ?? throw new InvalidOperationException("That entity isn't on this case.");
        if (!IsAccountType(entity.Type))
            throw new InvalidOperationException("Only an account (or an email address that is one) can be looked up in the directory.");
        return entity;
    }

    private void Require(Permission permission, [System.Runtime.CompilerServices.CallerMemberName] string action = "")
    {
        if (!_user.Has(permission)) throw new ForbiddenException(permission, action);
    }
}
