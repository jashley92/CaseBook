using IncidentManager.Application.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Work;

/// <summary>A user's calendar feed credential and how long it lasts.</summary>
public sealed record AgendaFeedLink(string Token, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);

/// <summary>
/// S-12: the personal agenda feed link's lifecycle. The token (an HMAC over the user and an issue time) is stable
/// per user until they reset it, so a subscribed calendar keeps working; resetting voids every earlier link for that
/// user only, a link lapses after <see cref="MaxAge"/>, and it stops working once the user holds no CaseBook role.
/// Before this, a link never expired and the only way to kill one was rotating the server key for everyone.
/// </summary>
public sealed class AgendaFeedService
{
    /// <summary>How long a feed link works before the user has to reset (re-issue) it.</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(365);

    private readonly IAppDbContextFactory _factory;
    private readonly IAgendaFeedTokens _tokens;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public AgendaFeedService(IAppDbContextFactory factory, IAgendaFeedTokens tokens, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _tokens = tokens;
        _user = user;
        _clock = clock;
    }

    public bool Enabled => _tokens.Enabled;

    /// <summary>The current user's feed link, issued on first request; null when the feed is off or the user unknown.</summary>
    public Task<AgendaFeedLink?> GetMyLinkAsync(CancellationToken ct = default) => IssueAsync(reset: false, ct);

    /// <summary>Voids the current user's earlier feed links and issues a new one.</summary>
    public Task<AgendaFeedLink?> ResetMyLinkAsync(CancellationToken ct = default) => IssueAsync(reset: true, ct);

    private async Task<AgendaFeedLink?> IssueAsync(bool reset, CancellationToken ct)
    {
        if (!_tokens.Enabled || !_user.IsAuthenticated) return null;
        using var db = _factory.CreateDbContext();
        var row = await db.Users.FirstOrDefaultAsync(u => u.Sid == _user.UserId, ct);
        if (row is null) return null;

        if (reset || row.FeedLinkIssuedAtUtc is null || Expired(row.FeedLinkIssuedAtUtc.Value))
        {
            row.FeedLinkIssuedAtUtc = ToSecond(_clock.UtcNow);   // the token carries whole seconds
            await db.SaveChangesAsync(ct);
        }

        var issued = row.FeedLinkIssuedAtUtc!.Value;
        var token = _tokens.Issue(_user.UserId, issued);
        return token is null ? null : new AgendaFeedLink(token, issued, issued + MaxAge);
    }

    /// <summary>
    /// The user a presented feed token belongs to, or null if it's forged, superseded by a reset, expired, or its
    /// owner no longer holds any CaseBook role.
    /// </summary>
    public async Task<string?> ResolveAsync(string? token, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token) || !_tokens.TryValidate(token, out var userId, out var issued)) return null;
        if (Expired(issued)) return null;

        using var db = _factory.CreateDbContext();
        var row = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Sid == userId, ct);
        if (row?.FeedLinkIssuedAtUtc is not { } current || ToSecond(current) != issued) return null;
        if (string.IsNullOrWhiteSpace(row.RolesCsv)) return null;
        return userId;
    }

    private bool Expired(DateTimeOffset issued) => _clock.UtcNow >= issued + MaxAge;

    private static DateTimeOffset ToSecond(DateTimeOffset t) => DateTimeOffset.FromUnixTimeSeconds(t.ToUnixTimeSeconds());
}
