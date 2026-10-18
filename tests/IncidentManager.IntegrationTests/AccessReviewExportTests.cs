using System.Collections.Concurrent;
using System.Net;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-15 through the real host (Program.cs): <c>/export/access-review.csv</c> is the review as CSV, recorded in the access
/// log and streamed as SIEM 5304 like every export, and refuses a passive load. The development sign-in is an
/// administrator. All data lives in a temp folder, as in <see cref="HostStartupSmokeTests"/>.
/// </summary>
public sealed class AccessReviewExportTests : IDisposable
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(90);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "casebook-access-review", Guid.NewGuid().ToString("N"));
    private readonly Sink _siem = new();

    private sealed class Sink : ISecurityEventSink
    {
        public ConcurrentQueue<SecurityEvent> Events { get; } = new();
        public void Emit(SecurityEvent e) => Events.Enqueue(e);
    }

    public AccessReviewExportTests() => Directory.CreateDirectory(_dir);

    private WebApplicationFactory<Program> Factory() => new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
    {
        b.UseEnvironment("Development");
        b.UseSetting("ConnectionStrings:Default", $"Data Source={Path.Combine(_dir, "casebook.db")}");
        b.UseSetting("Database:Provider", "Sqlite");
        b.UseSetting("EvidenceStore:RootPath", Path.Combine(_dir, "evidence"));
        b.UseSetting("ReportOutput:RootPath", Path.Combine(_dir, "reports"));
        b.UseSetting("ReportBranding:RootPath", Path.Combine(_dir, "branding"));
        b.UseSetting("Integrity:SigningKeyPath", Path.Combine(_dir, "keys", "seal-signing.pem"));
        b.UseSetting("Integrity:ExportPath", Path.Combine(_dir, "seals"));
        b.UseSetting("Integrity:AutoSeal:Enabled", "false");
        b.ConfigureTestServices(s => s.AddSingleton<ISecurityEventSink>(_siem));
    });

    [Fact]
    public async Task The_access_review_downloads_as_csv_with_the_access_log_and_siem_5304()
    {
        var work = Task.Run(async () =>
        {
            await using var factory = Factory();
            using var client = factory.CreateClient();

            using var asImage = new HttpRequestMessage(HttpMethod.Get, "/export/access-review.csv");
            asImage.Headers.Add("Sec-Fetch-Dest", "image");
            (await client.SendAsync(asImage)).StatusCode.Should().Be(HttpStatusCode.Forbidden, "BUG-186: a passive load isn't the person's");

            var csv = await client.GetAsync("/export/access-review.csv");
            csv.StatusCode.Should().Be(HttpStatusCode.OK);
            csv.Content.Headers.ContentType!.MediaType.Should().Be("text/csv");
            var fileName = csv.Content.Headers.ContentDisposition!.FileName!.Trim('"');
            fileName.Should().MatchRegex(@"^access-review-\d{8}-\d{4}\.csv$");
            var text = await csv.Content.ReadAsStringAsync();
            text.TrimStart('﻿').Should().StartWith("# CaseBook access review, generated ");
            text.Should().Contain("# Last recorded review: none").And.Contain("section,subject,detail,access,via,last_seen_utc,expires_utc,flag")
                .And.Contain("Broad access,", "the seeded roles that see every case");

            using var scope = factory.Services.CreateScope();
            await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync();
            (await db.CaseAccessEvents.CountAsync(e => e.AccessType == AccessType.Export && e.TargetLabel == fileName))
                .Should().Be(1, "the download is in the access log; the refused passive load isn't");
            _siem.Events.Should().ContainSingle(e => e.EventId == SecurityEventIds.DataExported && e.Detail == fileName);
        });
        (await Task.WhenAny(work, Task.Delay(Limit))).Should().BeSameAs(work, "the host should start and answer in time");
        await work;
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
