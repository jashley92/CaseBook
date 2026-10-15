using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Web.Components.Pages.Workspace;
using IncidentManager.Web.Services;
using Microsoft.AspNetCore.Components;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-509: a workspace rebuilt in place (the time-mode toggle) starts from the address it last wrote with
/// replaceState, not the router's stale one; any navigation makes the router's address the real one again.</summary>
public sealed class CaseTabsStateTests
{
    private static readonly Guid CaseA = Guid.Parse("6f1d2c3b-0000-4000-8000-0000000000a1");
    private static readonly Guid CaseB = Guid.Parse("6f1d2c3b-0000-4000-8000-0000000000b2");
    private static readonly Guid FileId = Guid.Parse("6f1d2c3b-0000-4000-8000-0000000000f3");

    private sealed class TestNav : NavigationManager
    {
        public TestNav(string uri) => Initialize("https://host/", uri);

        /// <summary>A navigation: the address changes, then LocationChanged is raised.</summary>
        public void Go(string relative)
        {
            Moved(relative);
            NotifyLocationChanged(false);
        }

        /// <summary>The address has changed, but LocationChanged hasn't reached the state yet (the router hears first).</summary>
        public void Moved(string relative) => Uri = ToAbsoluteUri(relative).ToString();

        protected override void NavigateToCore(string uri, NavigationOptions options) => Go(uri);
    }

    private static (CaseTabsState State, TestNav Nav) Opened(string link)
    {
        var nav = new TestNav($"https://host/{link}");
        return (new CaseTabsState(new CaseTabsService(null!, null!, null!, null!), nav), nav);
    }

    [Fact]
    public void A_page_rebuilt_in_place_gets_the_address_last_written_not_the_spent_link()
    {
        var (state, _) = Opened($"cases/{CaseA}?tab=Timeline&entry={Guid.NewGuid()}");
        state.Remember(CaseA, CaseViews.Url(CaseA, "Tasks"));

        state.WrittenUrlFor(CaseA).Should().Be(CaseViews.Url(CaseA, "Tasks"));
    }

    [Fact]
    public void Nothing_written_yet_means_the_routers_address_stands()
    {
        var (state, _) = Opened($"cases/{CaseA}?entry={Guid.NewGuid()}");

        state.WrittenUrlFor(CaseA).Should().BeNull("a first load opens its deep link");
    }

    [Fact]
    public void Any_navigation_since_makes_the_routers_address_the_real_one()
    {
        var link = $"cases/{CaseA}?tab=Timeline&entry={Guid.NewGuid()}";
        var (state, nav) = Opened(link);
        state.Remember(CaseA, CaseViews.Url(CaseA, "Tasks"));

        nav.Go("cases?scope=all");
        nav.Go(link);   // the same link followed again opens its entry again

        state.WrittenUrlFor(CaseA).Should().BeNull();
    }

    [Fact]
    public void A_navigation_the_router_has_built_before_this_hears_of_it_is_not_taken_for_a_rebuild()
    {
        var (state, nav) = Opened($"cases/{CaseA}");
        state.Remember(CaseA, CaseViews.Url(CaseA, "Tasks"));

        nav.Moved($"cases/{CaseA}?tab=Timeline&entry={Guid.NewGuid()}");   // Back, Forward or a link, mid-dispatch

        state.WrittenUrlFor(CaseA).Should().BeNull();
    }

    [Fact]
    public void Another_case_is_not_given_this_ones_address()
    {
        var (state, _) = Opened($"cases/{CaseA}");
        state.Remember(CaseA, CaseViews.Url(CaseA, "Tasks"));

        state.WrittenUrlFor(CaseB).Should().BeNull();
    }

    [Fact]
    public void A_rewrite_after_the_rebuild_is_still_honoured_on_the_next_one()
    {
        var (state, _) = Opened($"cases/{CaseA}?entity={Guid.NewGuid()}");
        state.Remember(CaseA, CaseViews.Url(CaseA, "Timeline"));
        state.Remember(CaseA, CaseViews.Url(CaseA, "Entities", FileId));

        state.WrittenUrlFor(CaseA).Should().Be(CaseViews.Url(CaseA, "Entities", FileId));
        state.UrlFor(CaseA).Should().Be(CaseViews.Url(CaseA, "Entities", FileId), "the tab strip's return is unchanged");
    }

    [Fact]
    public void The_written_address_reads_back_as_its_part_and_panel()
    {
        CaseViews.Read(CaseViews.Url(CaseA, "Closeout", FileId)).Should().Be(("Closeout", (Guid?)FileId));
        CaseViews.Read(CaseViews.Url(CaseA, "a&b")).Should().Be(("a&b", (Guid?)null));
        CaseViews.Read($"cases/{CaseA}").Should().Be(((string?)null, (Guid?)null));
        CaseViews.Read($"cases/{CaseA}?tab=Tasks&evidence=half-a-guid").Should().Be(("Tasks", (Guid?)null));
    }
}
