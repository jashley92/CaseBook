using FluentAssertions;
using IncidentManager.Infrastructure.Storage;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// PROD-47: with no template path configured (a server upgraded from an older release keeps its old
/// appsettings.Production.json), templates go beside the report-logo store — the data root — never the web root.
/// </summary>
public class ReportTemplateStoreTests
{
    [Fact]
    public void Unset_path_sits_beside_the_branding_store()
    {
        var dataRoot = Path.Combine(Path.GetTempPath(), "casebook-data");
        FileReportTemplateStore.ResolveRoot(null, Path.Combine(dataRoot, "branding"))
            .Should().Be(Path.Combine(dataRoot, "report-templates"));
        FileReportTemplateStore.ResolveRoot("  ", Path.Combine(dataRoot, "branding") + Path.DirectorySeparatorChar)
            .Should().Be(Path.Combine(dataRoot, "report-templates"));
    }

    [Fact]
    public void A_configured_path_wins() =>
        FileReportTemplateStore.ResolveRoot(@"D:\CaseBookData\tpl", @"D:\CaseBookData\branding").Should().Be(@"D:\CaseBookData\tpl");

    [Fact]
    public async Task The_folder_is_only_created_on_first_upload()
    {
        var root = Path.Combine(Path.GetTempPath(), "casebook-tpl-" + Guid.NewGuid().ToString("N"));
        var store = new FileReportTemplateStore(
            Microsoft.Extensions.Options.Options.Create(new ReportTemplateOptions { RootPath = root }),
            Microsoft.Extensions.Options.Options.Create(new ReportBrandingOptions()));

        Directory.Exists(root).Should().BeFalse("starting the app must not need a writable template folder");
        (await store.GetAsync(Guid.NewGuid())).Should().BeNull();

        var id = Guid.NewGuid();
        await store.SaveAsync(id, [1, 2, 3]);
        (await store.GetAsync(id)).Should().Equal(1, 2, 3);
        Directory.Delete(root, recursive: true);
    }
}
