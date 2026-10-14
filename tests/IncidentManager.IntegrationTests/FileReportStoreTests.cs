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

    [Theory]
    [InlineData("2026|01\"x\"_Report_v1.docx", "2026_01_x__Report_v1.docx")]
    [InlineData("2026:01_Report_v1.docx", "2026_01_Report_v1.docx")]          // not an NTFS alternate data stream
    [InlineData("a/b\\c<d>e?f*_Report_v1.docx", "a_b_c_d_e_f__Report_v1.docx")]
    [InlineData("CON.docx", "_CON.docx")]
    [InlineData("trailing. .docx", "trailing.docx")]
    public async Task A_case_number_with_characters_a_file_name_cant_hold_still_stores(string generated, string onDisk /* BUG-362 */)
    {
        var store = new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = _root }));
        var caseId = Guid.NewGuid();

        var stored = await store.SaveAsync(caseId, generated, [7, 8, 9]);

        stored.StoragePath.Should().Be($"{caseId:N}/{onDisk}");
        Directory.GetFiles(Path.Combine(_root, caseId.ToString("N"))).Select(Path.GetFileName).Should().Equal(onDisk);
        await using var s = await store.OpenReadAsync(stored.StoragePath);
        using var ms = new MemoryStream();
        await s.CopyToAsync(ms);
        ms.ToArray().Should().Equal(7, 8, 9);
    }

    [Fact]
    public async Task A_long_name_is_capped_on_disk(/* BUG-362 */)
    {
        var store = new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = _root }));
        var caseId = Guid.NewGuid();
        var stored = await store.SaveAsync(caseId, new string('x', 300) + "_Report_v1.docx", [1]);
        var name = stored.StoragePath[(stored.StoragePath.IndexOf('/') + 1)..];
        name.Length.Should().BeLessThanOrEqualTo(155);
        name.Should().EndWith(".docx");
    }

    [Fact]
    public async Task A_write_that_fails_part_way_leaves_no_file(/* BUG-82 */)
    {
        var store = new FileReportStore(Options.Create(new ReportOutputOptions { RootPath = _root }));
        var caseId = Guid.NewGuid();
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await store.Invoking(s => s.SaveAsync(caseId, "CASE_v1.docx", new byte[1024], cancelled.Token))
            .Should().ThrowAsync<OperationCanceledException>();

        Directory.GetFiles(Path.Combine(_root, caseId.ToString("N"))).Should().BeEmpty("no partial file, under any name");
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }
}
