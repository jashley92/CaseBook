using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Updates;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>PROD-49: reading the GitHub Releases API for the update check, strictly.</summary>
public sealed class ReleaseFeedTests
{
    private const string Repo = "jashley92/CaseBook";

    private static object Release(string tag, bool draft = false, bool prerelease = false, string body = "Notes",
        string? html = null, string? assetHost = null) => new
    {
        tag_name = tag,
        draft,
        prerelease,
        body,
        published_at = "2026-10-13T12:00:00Z",
        html_url = html ?? $"https://github.com/{Repo}/releases/tag/{tag}",
        assets = new[]
        {
            new { name = $"casebook-{tag}.zip", browser_download_url = $"{assetHost ?? $"https://github.com/{Repo}"}/releases/download/{tag}/casebook-{tag}.zip" },
            new { name = $"casebook-{tag}.zip.sha256", browser_download_url = $"https://github.com/{Repo}/releases/download/{tag}/casebook-{tag}.zip.sha256" },
        },
    };

    private static IReadOnlyList<AvailableRelease> Newer(Version current, params object[] releases) =>
        ReleaseFeed.Newer(JsonSerializer.Serialize(releases), Repo, current);

    [Fact]
    public void Lists_every_newer_release_newest_first()
    {
        var found = Newer(new Version(1, 5, 7), Release("v1.5.6"), Release("v1.6.0"), Release("v1.5.8"), Release("v1.5.7"));

        found.Select(r => r.Tag).Should().Equal("v1.6.0", "v1.5.8");
        found[0].BundleUrl.Should().Be($"https://github.com/{Repo}/releases/download/v1.6.0/casebook-v1.6.0.zip");
        found[0].Sha256Url.Should().EndWith(".zip.sha256");
        found[0].PublishedAtUtc.Should().Be(new DateTimeOffset(2026, 10, 13, 12, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public void The_running_release_and_older_ones_are_up_to_date()
    {
        Newer(new Version(1, 6, 0), Release("v1.6.0"), Release("v1.5.9")).Should().BeEmpty();
    }

    [Fact]
    public void Drafts_prereleases_and_odd_tags_are_skipped()
    {
        var found = Newer(new Version(1, 5, 0),
            Release("v1.7.0", draft: true), Release("v1.6.1", prerelease: true),
            Release("v1.6.0-rc1"), Release("1.6.0"), Release("latest"), Release("v1.5.1"));

        found.Select(r => r.Tag).Should().Equal("v1.5.1");
    }

    [Fact]
    public void Links_outside_this_repository_are_dropped()
    {
        var found = Newer(new Version(1, 5, 0),
            Release("v1.6.0", html: "https://evil.example/casebook", assetHost: "https://evil.example/x"));

        found[0].PageUrl.Should().Be($"https://github.com/{Repo}/releases/tag/v1.6.0");
        found[0].BundleUrl.Should().BeNull();
        found[0].Sha256Url.Should().NotBeNull();
    }

    [Fact]
    public void Long_notes_are_cut()
    {
        var found = Newer(new Version(1, 5, 0), Release("v1.6.0", body: new string('x', ReleaseFeed.MaxNotesChars + 500)));
        found[0].Notes.Length.Should().BeLessThan(ReleaseFeed.MaxNotesChars + 10);
    }

    [Fact]
    public void A_response_that_isnt_a_list_is_refused()
    {
        var act = () => ReleaseFeed.Newer("""{"message":"Not Found"}""", Repo, new Version(1, 0, 0));
        act.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData("1.6.0+a1b2c3d4e5", "1.6.0")]
    [InlineData("v1.5.9", "1.5.9")]
    [InlineData("1.6.0-rc.1+abc", "1.6.0")]
    [InlineData("1.6", null)]
    [InlineData("nonsense", null)]
    public void Versions_read_as_three_parts(string text, string? expected)
    {
        AppVersionInfo.ParseVersion(text)?.ToString().Should().Be(expected);
        if (expected is null) AppVersionInfo.ParseVersion(text).Should().BeNull();
    }

    [Theory]
    [InlineData("jashley92/CaseBook", true)]
    [InlineData("owner/repo.name", true)]
    [InlineData("https://github.com/x/y", false)]
    [InlineData("x/y/../z", false)]
    [InlineData("", false)]
    public void Only_owner_slash_name_is_a_repository(string repo, bool ok) =>
        ReleaseFeed.IsRepository(repo).Should().Be(ok);
}
