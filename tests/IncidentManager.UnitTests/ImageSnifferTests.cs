using System.Text;
using FluentAssertions;
using IncidentManager.Application.Evidence;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// The inline evidence endpoint trusts sniffed bytes, not the client Content-Type (S-04). Only genuine
/// raster images are recognised; active/mislabeled content (SVG, HTML) is refused.
/// </summary>
public class ImageSnifferTests
{
    [Fact]
    public void Png_is_recognised()
        => ImageSniffer.RasterContentType([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0])
            .Should().Be("image/png");

    [Fact]
    public void Jpeg_is_recognised()
        => ImageSniffer.RasterContentType([0xFF, 0xD8, 0xFF, 0xE0, 0, 0]).Should().Be("image/jpeg");

    [Fact]
    public void Gif_is_recognised()
        => ImageSniffer.RasterContentType(Encoding.ASCII.GetBytes("GIF89a...")).Should().Be("image/gif");

    [Fact]
    public void Webp_is_recognised()
        => ImageSniffer.RasterContentType(Encoding.ASCII.GetBytes("RIFF\0\0\0\0WEBPVP8 ")).Should().Be("image/webp");

    [Fact]
    public void Svg_is_refused()
        => ImageSniffer.RasterContentType(Encoding.ASCII.GetBytes("<svg xmlns=")).Should().BeNull();

    [Fact]
    public void Html_is_refused()
        => ImageSniffer.RasterContentType(Encoding.ASCII.GetBytes("<!DOCTYPE html>")).Should().BeNull();

    [Fact]
    public void Too_short_is_refused()
        => ImageSniffer.RasterContentType([0x89, 0x50]).Should().BeNull();

    [Fact]
    public void Empty_is_refused()
        => ImageSniffer.RasterContentType(ReadOnlySpan<byte>.Empty).Should().BeNull();
}
