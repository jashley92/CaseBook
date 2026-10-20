using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Web.Services;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Administration search: an everyday word finds the setting ("upload size" is the largest evidence file), a page is found
/// by what it's for, a server-only setting says it's set on the host, and every in-app setting links to the page it's
/// edited on, scrolled to it.
/// </summary>
public sealed class AdminSearchIndexTests
{
    [Theory]
    [InlineData("upload size", "Evidence:MaxUploadMB")]
    [InlineData("free space", "Evidence:MinFreeSpaceGB")]
    [InlineData("timeout", "Security:IdleTimeoutMinutes")]
    [InlineData("from address", "Email:From")]
    [InlineData("Evidence:StorageQuotaGB", "Evidence:StorageQuotaGB")]
    public void An_everyday_word_or_the_key_finds_the_setting_first(string query, string key)
    {
        var first = AdminSearchIndex.Search(query)[0];
        first.Key.Should().Be(key);
        first.Href.Should().Be(AdminSearchIndex.SettingHref(key)).And.EndWith("#" + key, "it lands scrolled to the setting");
    }

    [Fact]
    public void A_page_is_found_by_what_it_is_for()
    {
        AdminSearchIndex.Search("logo").Should().Contain(h => h.Kind == AdminSearchKind.Page && h.Href == "admin/settings/identity");
        AdminSearchIndex.Search("api key").Should().Contain(h => h.Kind == AdminSearchKind.Page && h.Href == "admin/api-tokens");
    }

    [Fact]
    public void A_server_only_setting_says_it_is_set_on_the_host()
    {
        var hit = AdminSearchIndex.Search("connection string").Should().ContainSingle(h => h.Kind == AdminSearchKind.ServerSetting).Subject;
        hit.Href.Should().Be("admin/settings/server");
        hit.Where.Should().Contain("set on the host");
    }

    [Fact]
    public void Every_in_app_setting_links_to_the_page_it_is_edited_on()
    {
        SettingsCatalog.Editable.Where(d => !AdminSearchIndex.SettingHref(d.Key).StartsWith("admin/settings/", StringComparison.Ordinal)
                                            || AdminSearchIndex.SettingHref(d.Key).StartsWith("admin/settings/source", StringComparison.Ordinal))
            .Select(d => d.Key).Should().BeEmpty();
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("x")]
    [InlineData("zzqqnothing")]
    public void A_query_too_short_or_matching_nothing_finds_nothing(string query) =>
        AdminSearchIndex.Search(query).Should().BeEmpty();
}
