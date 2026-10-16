using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.ApiTokens;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Notifications;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// C4 / BUG-591: a role name with a comma (allowed before v1.5.1) must survive every comma-separated role list it is
/// stored in: "Readers,SysAdmin" is one role, not Readers and SysAdmin. Every reader and writer goes through RoleList;
/// a source scan fails on a new one that splits or joins a role list itself.
/// </summary>
public sealed partial class LegacyRoleNameTests
{
    // Role-list splits and joins that aren't RoleList's, by file, with why.
    private static readonly Dictionary<string, string> Reviewed = new(StringComparer.Ordinal)
    {
        ["RoleList.cs"] = "the one splitter and joiner",
        // Another owner's file (Infrastructure): reads a token's roles back from its audit JSON for the row-hash backfill.
        // Reported with BUG-591; a legacy comma name there makes the backfill skip the row (it compares sets), not grant.
        ["RowHashBackfill.cs"] = "other owner; reported",
    };

    [Fact]
    public void Every_role_list_is_split_and_joined_by_RoleList()
    {
        var root = Path.Combine(RepoRoot(), "src");
        var offenders = new List<string>();
        foreach (var file in Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
                     .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
                     .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                                 && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)))
        {
            if (Reviewed.ContainsKey(Path.GetFileName(file))) continue;
            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
                if (CommaListCall().IsMatch(lines[i]) && lines[i].Contains("role", StringComparison.OrdinalIgnoreCase))
                    offenders.Add($"{Path.GetRelativePath(root, file)}:{i + 1}");
        }
        offenders.Should().BeEmpty("a role list is read with RoleList.Split and written with RoleList.Join, so a legacy name with a comma stays one role");
    }

    private const string Legacy = "Readers591,SysAdmin";

    // "Readers591,SysAdmin" grants nothing that sees cases; SysAdmin sees everything.
    private sealed class Roles : IRoleDirectory
    {
        private static readonly Dictionary<string, Permission[]> Known = new(StringComparer.OrdinalIgnoreCase)
        {
            [Legacy] = [Permission.ApproveReports],
            ["Readers 591, Admins"] = [Permission.ApproveReports],
            ["SysAdmin"] = [Permission.ViewCases, Permission.ViewAllCases, Permission.ViewRestricted, Permission.Administer],
            ["Analyst"] = [Permission.ViewCases],
        };
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) =>
            roleNames.SelectMany(r => Known.GetValueOrDefault(r) ?? []).ToHashSet();
        public bool IsRole(string name) => Known.ContainsKey(name);
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => new HashSet<string>();
        public void Invalidate() { }
    }

    [Theory]
    [InlineData("Readers591,SysAdmin", new[] { "Readers591,SysAdmin" })]
    [InlineData("Analyst,Readers591,SysAdmin", new[] { "Analyst", "Readers591,SysAdmin" })]
    [InlineData("Readers591,SysAdmin,Analyst", new[] { "Readers591,SysAdmin", "Analyst" })]
    [InlineData("Readers 591, Admins,Analyst", new[] { "Readers 591, Admins", "Analyst" })]   // a space after the comma, kept
    [InlineData("SysAdmin, Analyst,,", new[] { "SysAdmin", "Analyst" })]
    [InlineData("", new string[0])]
    public void Known_names_with_a_comma_are_read_whole(string csv, string[] expected)
    {
        var roles = new Roles();
        RoleList.Split(csv, roles.IsRole).Should().Equal(expected);
        RoleList.Split(RoleList.Join(RoleList.Split(csv, roles.IsRole)), roles.IsRole).Should().Equal(expected, "it round-trips");
    }

    [Fact]
    public void A_legacy_name_doesnt_grant_the_role_it_ends_with()
    {
        var roles = new Roles();
        var user = new UserSummary("u1", "U", null, null, Legacy);
        CaseAudience.CanSee(false, null, [], user, roles).Should().BeFalse("Readers591,SysAdmin isn't SysAdmin");
        ReminderAudience.GrantsViewCases(Legacy, roles).Should().BeFalse();
        ReminderAudience.GrantsViewCases("Analyst," + Legacy, roles).Should().BeTrue();
    }

    private sealed class Ad(IReadOnlySet<string> roles) : ITokenOwnerCheck
    {
        public Task<OwnerAccess?> CheckAsync(string ownerUserId, CancellationToken ct = default) =>
            Task.FromResult<OwnerAccess?>(new OwnerAccess(true, roles));
    }

    [Fact]
    public async Task The_directorys_answer_keeps_a_legacy_name_whole()
    {
        var users = new EntitlementUsers(("u1", "Analyst"));
        var audience = new ReminderAudience(users, new Roles(), new Ad(new HashSet<string> { Legacy }));
        (await audience.EntitledAsync("u1")).Should().BeFalse("the directory maps them to Readers591,SysAdmin only");
    }

    [Fact]
    public async Task Start_up_finds_legacy_names_and_every_reader_without_a_directory_keeps_them_whole()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options;
        await using (var db = new AppDbContext(options))
        {
            await db.Database.EnsureCreatedAsync();
            db.Roles.Add(new Role { Name = "Startup591,SysAdmin", PermissionsCsv = "ApproveReports", UpdatedBy = "test" });
            db.Roles.Add(new Role { Name = "Plain591", PermissionsCsv = "ViewCases", UpdatedBy = "test" });
            await db.SaveChangesAsync();
        }
        var log = new ListLogger();
        var check = new IncidentManager.Application.Admin.LegacyRoleNameCheck(Scopes(new TestDbContextFactory(options)), log);

        await check.StartAsync(CancellationToken.None);

        check.Found.Should().Equal("Startup591,SysAdmin");
        RoleList.LegacyNames.Should().Contain("Startup591,SysAdmin").And.NotContain("Plain591");
        log.Warnings.Should().ContainSingle().Which.Should().Contain("Startup591,SysAdmin");
        new ApiToken { RolesCsv = "Analyst,Startup591,SysAdmin" }.GetRoles().Should().Equal("Analyst", "Startup591,SysAdmin");
    }

    [Fact]
    public async Task Start_up_with_no_database_yet_says_so_and_carries_on()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();   // no schema
        var log = new ListLogger();
        var check = new IncidentManager.Application.Admin.LegacyRoleNameCheck(Scopes(
            new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options)), log);

        await check.StartAsync(CancellationToken.None);

        check.Found.Should().BeEmpty();
        log.Errors.Should().ContainSingle();
    }

    private static Microsoft.Extensions.DependencyInjection.IServiceScopeFactory Scopes(IAppDbContextFactory factory)
    {
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        Microsoft.Extensions.DependencyInjection.ServiceCollectionServiceExtensions.AddSingleton(services, factory);
        return Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions
            .GetRequiredService<Microsoft.Extensions.DependencyInjection.IServiceScopeFactory>(
                Microsoft.Extensions.DependencyInjection.ServiceCollectionContainerBuilderExtensions.BuildServiceProvider(services));
    }

    private sealed class ListLogger :ILogger<IncidentManager.Application.Admin.LegacyRoleNameCheck>
    {
        public List<string> Warnings { get; } = [];
        public List<string> Errors { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning) Warnings.Add(formatter(state, exception));
            if (logLevel >= LogLevel.Error) Errors.Add(formatter(state, exception));
        }
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }

    // A split on ',' or a join with ',' / ",".
    [GeneratedRegex(@"\.Split\(\s*','|string\.Join\(\s*(?:','|"",""|',')", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex CommaListCall();
}
