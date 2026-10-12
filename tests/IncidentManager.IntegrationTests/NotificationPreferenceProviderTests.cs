using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-97: a digest replaces per-item reminders only while digests are sent, and never replaces escalations.</summary>
public sealed class NotificationPreferenceProviderTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");

    public NotificationPreferenceProviderTests()
    {
        _connection.Open();
        using var db = NewContext();
        db.Database.EnsureCreated();
        db.UserNotificationPreferences.Add(new UserNotificationPreference { UserId = "mgr", DigestCadence = DigestCadence.Daily });
        db.SaveChanges();
    }

    private AppDbContext NewContext() => new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);

    private NotificationPreferenceProvider Provider(bool digestsOn)
    {
        var services = new ServiceCollection().AddScoped(_ => NewContext()).BuildServiceProvider();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Notifications:DigestScan:Enabled"] = digestsOn.ToString() })
            .Build();
        return new NotificationPreferenceProvider(services.GetRequiredService<IServiceScopeFactory>(), config);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task A_digest_replaces_reminders_only_while_digests_are_sent(bool digestsOn, bool suppressed)
    {
        var s = await Provider(digestsOn).GetAsync("mgr");

        s.Overdue.Should().Be(suppressed);
        s.DueSoon.Should().Be(suppressed);
        s.Escalation.Should().BeFalse("the digest doesn't cover other people's overdue tasks");
    }

    public void Dispose() => _connection.Dispose();
}
