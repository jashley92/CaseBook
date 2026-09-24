using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// S-13: on a restricted case, only people who can see it are offered for @mention and notified — an analyst outside
/// the team never receives the comment excerpt. An open case can mention anyone with case access.
/// </summary>
public sealed class RestrictedMentionTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic", RoleSet = [AppRole.Analyst] };
    private readonly Directory _dir = new();
    private readonly Capture _notifications = new();

    public RestrictedMentionTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    private CaseCommentService Svc() =>
        new(new TestDbContextFactory(Options()), _user, _clock, _dir, _notifications, new CodeRoles());

    private async Task<Guid> SeedAsync(bool restricted)
    {
        await using var db = new AppDbContext(Options());
        var c = Case.Open(2026, 3, "Insider", "Insider matter", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "ic", _clock.UtcNow);
        c.IncidentCommander = "ic";
        c.IsRestricted = restricted;
        c.Assign("teammate", "Teammate", CaseAssignmentRole.Analyst, "ic", _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c.Id;
    }

    [Fact]
    public async Task A_restricted_case_only_mentions_and_notifies_its_audience()
    {
        var id = await SeedAsync(restricted: true);

        (await Svc().MentionableAsync(id)).Select(u => u.UserId)
            .Should().BeEquivalentTo(["teammate", "legal"], "the team and a cleared role, not an outside analyst");

        await Svc().AddAsync(id, "@Teammate @Outsider @Legal see this", null, ["teammate", "outsider", "legal"]);

        _notifications.Mentioned.Should().BeEquivalentTo(["teammate", "legal"]);
    }

    [Fact]
    public async Task An_open_case_mentions_anyone_with_case_access()
    {
        var id = await SeedAsync(restricted: false);

        (await Svc().MentionableAsync(id)).Select(u => u.UserId)
            .Should().BeEquivalentTo(["teammate", "legal", "outsider"]);
    }

    /// <summary>Resolves built-in role names to their code-defined permissions.</summary>
    private sealed class CodeRoles : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) =>
            RoleDefinitions.PermissionsForRoleNames(roleNames);
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => new HashSet<string>();
        public void Invalidate() { }
    }

    private sealed class Directory : IUserDirectory
    {
        private readonly List<UserSummary> _all =
        [
            new("ic", "IC", null, null, "Analyst"),
            new("teammate", "Teammate", null, null, "Analyst"),
            new("outsider", "Outsider", null, null, "Analyst"),
            new("legal", "Legal", null, null, "LegalPrivacy"),
        ];
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => _all;
        public UserSummary? Resolve(string userId) => _all.FirstOrDefault(u => u.UserId == userId);
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }

    private sealed class Capture : ICaseNotifications
    {
        public List<string> Mentioned { get; } = new();
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName, CaseAssignmentRole role, string assignedByUserId, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnMentionedAsync(Case c, string byUserId, IReadOnlyCollection<string> mentionedUserIds, string commentExcerpt, CancellationToken ct = default)
        {
            Mentioned.AddRange(mentionedUserIds);
            return Task.CompletedTask;
        }
    }

    public void Dispose() => _connection.Dispose();
}
