using FluentAssertions;
using IncidentManager.Infrastructure.Storage;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-16: a stored report is never overwritten, so an earlier version's hash keeps verifying.</summary>
public sealed class FileReportStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "im-reportstore-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task A_taken_name_gets_a_suffix_and_the_first_file_is_kept()
    {
        var store = new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = _root }));
        var caseId = Guid.NewGuid();

        var first = await store.SaveAsync(caseId, "CASE_v1.docx", [1, 2, 3]);
        var second = await store.SaveAsync(caseId, "CASE_v1.docx", [4, 5, 6]);

        second.StoragePath.Should().NotBe(first.StoragePath).And.EndWith("CASE_v1-2.docx");
        await using var s = await store.OpenReadAsync(first.StoragePath);
        using var ms = new MemoryStream();
        await s.CopyToAsync(ms);
        ms.ToArray().Should().Equal(1, 2, 3);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }
}
