using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Notifications;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>WF-19: a task owner written as an email or UPN is reminded as the directory user it names.</summary>
public class TaskReminderAudienceTests
{
    private sealed class Directory : IUserDirectory
    {
        private readonly List<UserSummary> _all =
        [
            new("jsmith", "Jane Smith", "jane.smith@corp.example", "jane.smith@corp.example", "Analyst"),
            new("jdoe", "Jane Smith", "jdoe@corp.example", "jdoe@corp.example", "Analyst"),   // shares the display name
        ];
        public UserSummary? Resolve(string userId) => _all.FirstOrDefault(u => string.Equals(u.UserId, userId, StringComparison.OrdinalIgnoreCase));
        public IReadOnlyList<UserSummary> All() => _all;
        public string DisplayFor(string? userId) => userId ?? "";
        public string? EmailFor(string userId) => Resolve(userId)?.Email;
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public void Invalidate() { }
    }

    [Theory]
    [InlineData("jsmith", "jsmith")]
    [InlineData(" Jane.Smith@corp.example ", "jsmith")]
    [InlineData("JDOE@corp.example", "jdoe")]
    [InlineData("Jane Smith", "Jane Smith")]          // a display name two people share falls back, as before
    [InlineData("vendor@partner.example", "vendor@partner.example")]
    public void An_owner_named_by_email_or_upn_is_that_user(string owner, string expected) =>
        TaskReminderAudience.OwnerId(owner, new Directory()).Should().Be(expected);
}
