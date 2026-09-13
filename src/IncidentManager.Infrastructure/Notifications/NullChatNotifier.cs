using IncidentManager.Application.Abstractions;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// Default <see cref="IChatNotifier"/> for hosts that don't wire a chat webhook transport (tests, or a
/// non-Web host). Always disabled; posting is a no-op. The Web project registers the real HTTP-backed
/// <c>ChatWebhookNotifier</c>, which supersedes this.
/// </summary>
public sealed class NullChatNotifier : IChatNotifier
{
    public bool Enabled => false;
    public Task SendAsync(ChatNotification message, CancellationToken ct = default) => Task.CompletedTask;
}
