using IncidentManager.Application.Abstractions;

namespace IncidentManager.IntegrationTests;

/// <summary>CAP-01/CAP-06: a user directory holding just the people a test lists (an empty one for "nobody known").</summary>
internal sealed class ListedUserDirectory(params UserSummary[] users) : IUserDirectory
{
    public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv,
        CancellationToken ct = default) => Task.CompletedTask;
    public IReadOnlyList<UserSummary> All() => users;
    public UserSummary? Resolve(string userId) => users.FirstOrDefault(u => string.Equals(u.UserId, userId, StringComparison.OrdinalIgnoreCase));
    public string DisplayFor(string? userId) => userId is null ? "—" : Resolve(userId)?.DisplayName ?? userId;
    public string? EmailFor(string userId) => Resolve(userId)?.Email;
    public void Invalidate() { }

    /// <summary>A person with these built-in roles (comma-separated), emailed at userId@contoso.example.</summary>
    public static UserSummary User(string userId, string rolesCsv) =>
        new(userId, userId.ToUpperInvariant(), $"{userId}@contoso.example", $"{userId}@contoso.example", rolesCsv);
}
