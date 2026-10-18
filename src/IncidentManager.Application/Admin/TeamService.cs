using System.Security.Cryptography;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Common;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>
/// CAP-36: a team as the admin page, the pickers and the filters show it. <see cref="Members"/> are user ids, in order;
/// <see cref="CaseCount"/> counts the cases that name it (admin list only; 0 elsewhere). <see cref="Stamp"/> is the team
/// and its members as read (C9): an edit made from it is refused once either has changed.
/// </summary>
public sealed record TeamView(Guid Id, string Key, string Name, bool IsActive, string? DetectionSourceLabel,
    string? DetectionLinkTemplate, IReadOnlyList<string> Members, int CaseCount, string Stamp);

/// <summary>CAP-36: what the admin page saves for a team: its name, detection source, link template and members.</summary>
public sealed record TeamEdit(string Name, string? DetectionSourceLabel, string? DetectionLinkTemplate, IReadOnlyList<string> Members);

/// <summary>
/// CAP-36: administers the teams that own cases. Teams route and filter only (owner decision, 2026-10-18): a case's team
/// picks its chat webhook and detection source, and narrows lists and figures, but never who can see the case, which stays
/// ADR 0003's single need-to-know filter. Admins add, rename, re-describe and retire or restore teams and set who is in
/// them; each change is audited and hash-chained like other reference data and streamed as SIEM 5405. A team's key is
/// generated once from its first name and never changed or reused; teams are retired, never deleted, so every case that
/// names one still resolves. The team's chat webhook URL is a secret saved apart (CAP-40), never here.
/// </summary>
public sealed class TeamService
{
    /// <summary>The most members a team holds.</summary>
    public const int MaxMembers = 500;
    private const int MaxUserId = 200;

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ISecurityEventSink? _siem;

    public TeamService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, ISecurityEventSink? siem = null)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _siem = siem;
    }

    /// <summary>Every team, active and retired, by name, with its members and how many cases name it (the admin list).</summary>
    public async Task<List<TeamView>> ListAllAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var teams = await db.Teams.AsNoTracking().ToListAsync(ct);
        var members = await MembersAsync(db, null, ct);
        var uses = await db.Cases.AsNoTracking().Where(c => c.TeamId != null)
            .GroupBy(c => c.TeamId!.Value).Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count, ct);
        return Ordered(teams).Select(t => Project(t, members, uses.GetValueOrDefault(t.Id))).ToList();
    }

    /// <summary>Every team, active and retired, by name, without counts: what the filters and the case page show.</summary>
    public async Task<List<TeamView>> ListAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var teams = await db.Teams.AsNoTracking().ToListAsync(ct);
        var members = await MembersAsync(db, null, ct);
        return Ordered(teams).Select(t => Project(t, members, 0)).ToList();
    }

    /// <summary>The active teams the current user is a member of, by name: the New case form's default and a view's share.</summary>
    public async Task<List<TeamView>> MineAsync(CancellationToken ct = default)
    {
        var me = _user.UserId;
        using var db = _factory.CreateDbContext();
        var ids = await db.TeamMembers.AsNoTracking().Where(m => m.UserId == me).Select(m => m.TeamId).ToListAsync(ct);
        var teams = await db.Teams.AsNoTracking().Where(t => t.IsActive && ids.Contains(t.Id)).ToListAsync(ct);
        var members = await MembersAsync(db, ids, ct);
        return Ordered(teams).Select(t => Project(t, members, 0)).ToList();
    }

    /// <summary>The team with <paramref name="key"/> (ignoring case), active or retired, or null.</summary>
    public async Task<TeamView?> FindByKeyAsync(string? key, CancellationToken ct = default)
    {
        var k = key?.Trim();
        if (string.IsNullOrEmpty(k) || k.Length > Team.KeyMax) return null;
        return (await ListAsync(ct)).FirstOrDefault(t => string.Equals(t.Key, k, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The filter a URL's <c>team=</c> value names (<see cref="Cases.TeamScope.ResolveAsync"/>): what Program and Team
    /// workload pass to their figures, read the way the Cases list reads it.</summary>
    public async Task<Cases.TeamScope> ScopeAsync(string? key, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await Cases.TeamScope.ResolveAsync(db, key, ct);
    }

    /// <summary>A <c>team=</c> value as the pickers spell it: a team's key as stored when one matches ignoring case, <c>none</c>,
    /// or the value as given (a stale key, which lists nothing), so a link typed in another case shows its team picked.</summary>
    public static string PickerValue(IEnumerable<TeamView> teams, string? raw)
    {
        var k = raw?.Trim() ?? "";
        if (string.Equals(k, Cases.TeamScope.NoneKey, StringComparison.OrdinalIgnoreCase)) return Cases.TeamScope.NoneKey;
        return teams.FirstOrDefault(t => string.Equals(t.Key, k, StringComparison.OrdinalIgnoreCase))?.Key ?? k;
    }

    /// <summary>Why <paramref name="edit"/> can't be saved, or null. Names, labels and templates are checked as stored.</summary>
    public static string? Problem(TeamEdit edit)
    {
        var name = (edit.Name ?? "").Trim();
        if (name.Length == 0) return "Give the team a name.";
        if (name.Length > Team.NameMax) return $"A team name must be {Team.NameMax} characters or fewer.";
        if ((edit.DetectionSourceLabel ?? "").Trim().Length > Team.LabelMax)
            return $"The detection source label must be {Team.LabelMax} characters or fewer.";
        var template = (edit.DetectionLinkTemplate ?? "").Trim();
        if (template.Length > Team.LinkTemplateMax) return $"The link template must be {Team.LinkTemplateMax} characters or fewer.";
        if (Content.LinkTemplate.Problem(template) is { } bad) return $"The link template can't be used: {bad}";
        var members = edit.Members ?? [];
        if (members.Count > MaxMembers) return $"A team holds up to {MaxMembers} members.";
        if (members.Any(m => string.IsNullOrWhiteSpace(m) || m.Trim().Length > MaxUserId))
            return "A member is missing a user id, or has one longer than any user's.";
        return null;
    }

    /// <summary>Adds a team (active), with a key generated from its name. Returns its id.</summary>
    public async Task<Guid> CreateAsync(TeamEdit edit, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<TeamService>(_user);
        if (Problem(edit) is { } problem) throw new ArgumentException(problem);
        using var guard = await GuardGate.EnterAsync(ct);   // C1: the configuration import writes teams too
        using var db = _factory.CreateDbContext();
        var name = edit.Name.Trim();
        var existing = await db.Teams.AsNoTracking().Select(t => new { t.Key, t.Name }).ToListAsync(ct);
        if (existing.Any(t => string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"There's already a team named \"{name}\".");
        var now = _clock.UtcNow;
        var team = new Team
        {
            Key = UniqueKey(name, existing.Select(t => t.Key).ToHashSet(StringComparer.OrdinalIgnoreCase)),
            Name = name,
            DetectionSourceLabel = Blank(edit.DetectionSourceLabel),
            DetectionLinkTemplate = Blank(edit.DetectionLinkTemplate),
            IsActive = true,
            CreatedBy = _user.UserId,
            CreatedAtUtc = now,
        };
        db.Teams.Add(team);
        foreach (var m in Distinct(edit.Members))
            db.TeamMembers.Add(new TeamMember { TeamId = team.Id, UserId = m, AddedAtUtc = now, AddedBy = _user.UserId });
        await SaveAsync(db, ct);
        _siem.ReferenceDataChanged(_user, ReferenceDataKinds.Team, name, ReferenceDataAction.Created, team.Id);
        return team.Id;
    }

    /// <summary>
    /// Renames, re-describes and re-staffs a team. <paramref name="expectedStamp"/> is the <see cref="TeamView.Stamp"/> the
    /// page loaded: a team (or its members) changed since is refused, so a stale page never undoes another admin's edit.
    /// </summary>
    public async Task UpdateAsync(Guid id, TeamEdit edit, string? expectedStamp, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<TeamService>(_user);
        if (Problem(edit) is { } problem) throw new ArgumentException(problem);
        using var guard = await GuardGate.EnterAsync(ct);
        using var db = _factory.CreateDbContext();
        var team = await db.Teams.FirstOrDefaultAsync(t => t.Id == id, ct)
                   ?? throw new InvalidOperationException("That team no longer exists. Reload the page.");
        var rows = await db.TeamMembers.Where(m => m.TeamId == id).ToListAsync(ct);
        RequireStamp(team, rows, expectedStamp);
        var name = edit.Name.Trim();
        if (await db.Teams.AsNoTracking().Where(t => t.Id != id).Select(t => t.Name).ToListAsync(ct) is var names
            && names.Any(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"There's already a team named \"{name}\".");

        var now = _clock.UtcNow;
        var changed = team.Name != name || team.DetectionSourceLabel != Blank(edit.DetectionSourceLabel)
                      || team.DetectionLinkTemplate != Blank(edit.DetectionLinkTemplate);
        team.Name = name;
        team.DetectionSourceLabel = Blank(edit.DetectionSourceLabel);
        team.DetectionLinkTemplate = Blank(edit.DetectionLinkTemplate);
        if (changed) (team.ModifiedBy, team.ModifiedAtUtc) = (_user.UserId, now);

        var wanted = Distinct(edit.Members);
        var keep = wanted.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var gone = rows.Where(r => !keep.Contains(r.UserId)).ToList();
        db.TeamMembers.RemoveRange(gone);
        var have = rows.Select(r => r.UserId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var added = wanted.Where(m => !have.Contains(m)).ToList();
        foreach (var m in added)
            db.TeamMembers.Add(new TeamMember { TeamId = id, UserId = m, AddedAtUtc = now, AddedBy = _user.UserId });
        if (!changed && gone.Count == 0 && added.Count == 0) return;
        await SaveAsync(db, ct);
        _siem.ReferenceDataChanged(_user, ReferenceDataKinds.Team,
            changed ? name : $"{name} (members)", ReferenceDataAction.Changed, id);
    }

    /// <summary>Retires a team (no longer offered for cases; it stays on the cases that name it) or restores it.</summary>
    public async Task SetActiveAsync(Guid id, bool active, string? expectedStamp, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<TeamService>(_user);
        using var guard = await GuardGate.EnterAsync(ct);
        using var db = _factory.CreateDbContext();
        var team = await db.Teams.FirstOrDefaultAsync(t => t.Id == id, ct)
                   ?? throw new InvalidOperationException("That team no longer exists. Reload the page.");
        RequireStamp(team, await db.TeamMembers.AsNoTracking().Where(m => m.TeamId == id).ToListAsync(ct), expectedStamp);
        if (team.IsActive == active) return;
        team.IsActive = active;
        (team.ModifiedBy, team.ModifiedAtUtc) = (_user.UserId, _clock.UtcNow);
        await SaveAsync(db, ct);
        _siem.ReferenceDataChanged(_user, ReferenceDataKinds.Team, $"{team.Name} ({(active ? "restored" : "retired")})",
            ReferenceDataAction.Changed, id);
    }

    /// <summary>The words for an edit refused because the team changed since the page read it.</summary>
    public const string ChangedSinceOpened =
        "Someone changed this team since the page opened, so nothing was saved: it would have undone that. Reload the page, then make your change again.";

    private static void RequireStamp(Team team, IReadOnlyCollection<TeamMember> rows, string? expected)
    {
        if (expected is not null && !string.Equals(StampOf(team, rows.Select(r => r.UserId)), expected, StringComparison.Ordinal))
            throw new Cases.StaleEditException(StampOf(team, rows.Select(r => r.UserId)), ChangedSinceOpened);
    }

    // C1: a name taken by a save that landed between the check and this one (the unique index) is a worded refusal.
    private static async Task SaveAsync(IAppDbContext db, CancellationToken ct)
    {
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException ex)
        {
            throw new InvalidOperationException("Another change to the teams landed at the same moment. Reload the page and try again.", ex);
        }
    }

    /// <summary>The team and its members as read, hashed (C9): the row hash covers the team, the ids its members.</summary>
    internal static string StampOf(Team t, IEnumerable<string> members) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n',
            new[] { t.RowHash ?? "", t.Name, t.IsActive ? "1" : "0", t.DetectionSourceLabel ?? "", t.DetectionLinkTemplate ?? "" }
                .Concat(members.Order(StringComparer.OrdinalIgnoreCase))))));

    private static async Task<Dictionary<Guid, List<string>>> MembersAsync(IAppDbContext db, List<Guid>? only, CancellationToken ct)
    {
        var q = db.TeamMembers.AsNoTracking();
        if (only is not null) q = q.Where(m => only.Contains(m.TeamId));
        return (await q.Select(m => new { m.TeamId, m.UserId }).ToListAsync(ct))
            .GroupBy(m => m.TeamId)
            .ToDictionary(g => g.Key, g => g.Select(m => m.UserId).Order(StringComparer.OrdinalIgnoreCase).ToList());
    }

    private static IEnumerable<Team> Ordered(IEnumerable<Team> teams) =>
        teams.OrderBy(t => t.Name, StringComparer.CurrentCultureIgnoreCase).ThenBy(t => t.Key, StringComparer.Ordinal);

    private static TeamView Project(Team t, IReadOnlyDictionary<Guid, List<string>> members, int uses)
    {
        var m = members.GetValueOrDefault(t.Id) ?? [];
        return new TeamView(t.Id, t.Key, t.Name, t.IsActive, t.DetectionSourceLabel, t.DetectionLinkTemplate, m, uses, StampOf(t, m));
    }

    private static List<string> Distinct(IReadOnlyList<string>? members) =>
        (members ?? []).Select(m => m.Trim()).Where(m => m.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    /// <summary>A stable PascalCase key from the name ("SOC tier 1" → "SocTier1"), made unique with a number.</summary>
    internal static string UniqueKey(string name, ISet<string> used)
    {
        var sb = new StringBuilder(name.Length);
        var capNext = true;
        foreach (var ch in name)
        {
            if (char.IsAsciiLetterOrDigit(ch)) { sb.Append(capNext ? char.ToUpperInvariant(ch) : char.ToLowerInvariant(ch)); capNext = false; }
            else capNext = true;
        }
        var baseKey = sb.Length == 0 ? "Team" : sb.ToString();
        if (char.IsDigit(baseKey[0])) baseKey = "T" + baseKey;
        baseKey = TextFit.Cap(baseKey, Team.KeyMax - 4, marker: "")!;   // room for a number after it
        var key = baseKey;
        var n = 2;
        while (used.Contains(key)) key = string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{baseKey}{n++}");
        return key;
    }
}
