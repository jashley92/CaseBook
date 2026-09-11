using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.UnitTests;

/// <summary>Captures composed messages so notifier tests can assert on the branded HTML (E-03b).</summary>
public sealed class CapturingEmailSender : IEmailSender
{
    public List<EmailMessage> Sent { get; } = new();
    public bool Throw { get; init; }

    public Task SendAsync(EmailMessage message, CancellationToken ct = default)
    {
        if (Throw) throw new InvalidOperationException("smtp down");
        Sent.Add(message);
        return Task.CompletedTask;
    }

    public Task SendAsync(IReadOnlyCollection<string> to, string subject, string body, CancellationToken ct = default)
    {
        if (Throw) throw new InvalidOperationException("smtp down");
        Sent.Add(new EmailMessage(to, subject, body, body));
        return Task.CompletedTask;
    }
}

/// <summary>An empty branding store (no logo) for composing test emails.</summary>
public sealed class NoLogoBrandingStore : IReportBrandingStore
{
    public Task<ReportLogo?> GetLogoAsync(CancellationToken ct = default) => Task.FromResult<ReportLogo?>(null);
    public Task SaveLogoAsync(byte[] bytes, string contentType, CancellationToken ct = default) => Task.CompletedTask;
    public Task ClearLogoAsync(CancellationToken ct = default) => Task.CompletedTask;
}

/// <summary>Builds a real <see cref="EmailComposer"/> over in-memory config, for notifier/composition tests.</summary>
public static class TestEmail
{
    public static IConfiguration Config(params (string Key, string Value)[] config) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(config.Select(c => new KeyValuePair<string, string?>(c.Key, c.Value)))
            .Build();

    public static readonly IConfiguration EmptyConfig = Config();

    public static IEmailComposer Composer(params (string Key, string Value)[] config) =>
        new EmailComposer(Config(config), new NoLogoBrandingStore());
}
