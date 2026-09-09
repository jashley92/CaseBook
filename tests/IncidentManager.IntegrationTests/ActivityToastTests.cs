using FluentAssertions;
using IncidentManager.Web.Services;

namespace IncidentManager.IntegrationTests;

/// <summary>U-30: the live-collaboration toast phrase builder (pure; the caller prefixes the actor).</summary>
public class ActivityToastTests
{
    [Fact]
    public void Single_item_reads_with_an_article()
        => ActivityToast.Compose(new[] { "timeline entry" }).Should().Be("added a timeline entry");

    [Fact]
    public void Multiple_of_one_kind_are_counted_and_pluralised()
        => ActivityToast.Compose(new[] { "note", "note", "note" }).Should().Be("added 3 notes");

    [Fact]
    public void Entity_pluralises_irregularly()
        => ActivityToast.Compose(new[] { "entity", "entity" }).Should().Be("added 2 entities");

    [Fact]
    public void Two_kinds_join_with_and()
        => ActivityToast.Compose(new[] { "timeline entry", "note" })
            .Should().Be("added a timeline entry and a note");

    [Fact]
    public void Three_kinds_use_an_oxford_list()
        => ActivityToast.Compose(new[] { "timeline entry", "note", "note", "evidence item", "evidence item" })
            .Should().Be("added a timeline entry, 2 notes, and 2 evidence items");

    [Fact]
    public void Empty_falls_back_to_generic_changes()
        => ActivityToast.Compose(Array.Empty<string>()).Should().Be("added changes");
}
