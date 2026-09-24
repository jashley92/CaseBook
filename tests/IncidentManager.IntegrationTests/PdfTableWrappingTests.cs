using FluentAssertions;
using IncidentManager.Infrastructure.Reporting;
using PdfSharp.Drawing;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// PDF tables: MigraDoc only wraps at spaces/hyphens, so a token wider than its column (a SHA-256, a URL) used to
/// print across the neighbouring cells. The table helper now splits such tokens to the measured column width.
/// </summary>
public sealed class PdfTableWrappingTests
{
    private static (XGraphics Gfx, XFont Font) Measure()
    {
        // Constructing the generator runs its static ctor, which registers the embedded font resolver.
        _ = new ReportGenerator();
        return (XGraphics.CreateMeasureContext(new XSize(2000, 2000), XGraphicsUnit.Point, XPageDirection.Downwards),
            new XFont("DejaVu Sans", 9));
    }

    [Fact]
    public void A_hash_wider_than_its_column_is_split_into_chunks_that_each_fit_and_rejoin_exactly()
    {
        var (gfx, font) = Measure();
        const string sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        var maxWidth = 3.0 / 2.54 * 72;   // a 3 cm column

        var chunks = ReportGenerator.SplitToWidth(sha256, maxWidth, gfx, font);

        chunks.Should().HaveCountGreaterThan(1);
        chunks.Should().OnlyContain(c => gfx.MeasureString(c, font).Width <= maxWidth);
        string.Concat(chunks).Should().Be(sha256, "no characters may be lost or added — examiners copy hashes");
    }

    [Fact]
    public void A_url_prefers_to_break_after_a_separator()
    {
        var (gfx, font) = Measure();
        const string url = "https://o365-secure-login.contoso-insurance.example.attacker.test/path";

        var chunks = ReportGenerator.SplitToWidth(url, 3.5 / 2.54 * 72, gfx, font);

        string.Concat(chunks).Should().Be(url);
        chunks.Take(chunks.Count - 1).Select(c => c[c.Length - 1]).Should().OnlyContain(ch => "/.-_\\".Contains(ch),
            "each break should land after a URL separator when one is available");
    }
}
