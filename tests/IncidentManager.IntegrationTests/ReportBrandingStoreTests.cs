using FluentAssertions;
using IncidentManager.Infrastructure.Storage;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-215: a new logo takes the old one's place only once it's written.</summary>
public sealed class ReportBrandingStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "im-branding-tests", Guid.NewGuid().ToString("N"));

    private FileReportBrandingStore Store() => new(Options.Create(new ReportBrandingOptions { RootPath = _root }));

    [Fact]
    public async Task Replacing_the_logo_leaves_one_file_and_nothing_staged()
    {
        var store = Store();
        await store.SaveLogoAsync([1, 2, 3], "image/png");
        await store.SaveLogoAsync([4, 5], "image/jpeg");

        Directory.GetFiles(_root).Select(Path.GetFileName).Should().Equal("logo.jpg");
        var logo = await store.GetLogoAsync();
        logo!.ContentType.Should().Be("image/jpeg");
        logo.Bytes.Should().Equal(4, 5);
    }

    [Fact]
    public async Task A_logo_that_fails_to_write_leaves_the_current_one()
    {
        var store = Store();
        await store.SaveLogoAsync([1, 2, 3], "image/png");

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await store.Invoking(s => s.SaveLogoAsync([9, 9], "image/jpeg", cts.Token)).Should().ThrowAsync<OperationCanceledException>();

        Directory.GetFiles(_root).Select(Path.GetFileName).Should().Equal("logo.png");
        (await store.GetLogoAsync())!.Bytes.Should().Equal(1, 2, 3);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
