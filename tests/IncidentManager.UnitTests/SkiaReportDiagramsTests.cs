using FluentAssertions;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Reporting;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>PROD-46: the report pictures render as PNGs, wrap long chains, and skip empty pictures.</summary>
public class SkiaReportDiagramsTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 20, 9, 0, 0, TimeSpan.Zero);
    private readonly SkiaReportDiagrams _diagrams = new();

    private static DiagramStep Step(int n, params MitreTactic[] tactics) =>
        new(n, T0.AddMinutes(n * 10), tactics, $"T10{n:00}", "203[.]0[.]113[.]66", @"CONTOSO\jdoe");

    private static bool IsPng(byte[] b) => b.Length > 24 && b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47;
    private static int PngWidth(byte[] b) => (b[16] << 24) | (b[17] << 16) | (b[18] << 8) | b[19];

    [Fact]
    public void An_attack_chain_renders_as_a_print_resolution_png()
    {
        var images = _diagrams.AttackChain([Step(1, MitreTactic.InitialAccess), Step(2, MitreTactic.CredentialAccess, MitreTactic.Collection),
            Step(3, MitreTactic.Collection)]);

        images.Should().ContainSingle();
        IsPng(images[0]).Should().BeTrue();
        PngWidth(images[0]).Should().Be(2000, "drawn at 2× the 1000-unit layout width");
    }

    [Fact]
    public void A_long_chain_wraps_into_several_images()
    {
        var steps = Enumerable.Range(1, 13).Select(i => Step(i, MitreTactic.Execution)).ToList();

        _diagrams.AttackChain(steps).Should().HaveCount(3, "six steps per image");
    }

    [Fact]
    public void Nothing_to_draw_yields_nothing()
    {
        _diagrams.AttackChain([]).Should().BeEmpty();
        var a = new DiagramNode(Guid.NewGuid(), "a", EntityType.Host, EntityDisposition.Benign, null, null);
        _diagrams.EntityGraph([a], []).Should().BeNull("an entity graph needs at least one relationship");
    }

    [Fact]
    public void An_entity_graph_renders_with_or_without_a_saved_layout()
    {
        var ip = new DiagramNode(Guid.NewGuid(), "203[.]0[.]113[.]66", EntityType.IpAddress, EntityDisposition.Malicious, null, null);
        var host = new DiagramNode(Guid.NewGuid(), "FIN-WKS-07", EntityType.Host, EntityDisposition.Compromised, null, null);
        var edges = new[] { new DiagramEdge(host.Id, ip.Id, "communicated with") };

        IsPng(_diagrams.EntityGraph([ip, host], edges)!).Should().BeTrue();

        var laidOut = new[] { ip with { X = -120, Y = 40 }, host with { X = 200, Y = -80 } };
        IsPng(_diagrams.EntityGraph(laidOut, edges)!).Should().BeTrue();
    }
}
