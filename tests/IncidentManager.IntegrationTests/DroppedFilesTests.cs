using FluentAssertions;
using IncidentManager.Web.Components.Shared;
using Microsoft.AspNetCore.Components.Forms;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-341 (B2 review): reading a drop's files never throws for how many came.</summary>
public sealed class DroppedFilesTests
{
    private sealed class FakeFile(string name) : IBrowserFile
    {
        public string Name => name;
        public DateTimeOffset LastModified => DateTimeOffset.UnixEpoch;
        public long Size => 1;
        public string ContentType => "text/plain";
        public Stream OpenReadStream(long maxAllowedSize = 512000, CancellationToken cancellationToken = default) => new MemoryStream([1]);
    }

    private static InputFileChangeEventArgs Drop(int count) =>
        new(Enumerable.Range(0, count).Select(i => (IBrowserFile)new FakeFile($"f{i}.txt")).ToList());

    [Fact]
    public void Past_the_limit_is_an_answer_not_a_throw()
    {
        DroppedFiles.UpTo(Drop(51), 50).Should().BeNull();
        DroppedFiles.UpTo(Drop(50), 50).Should().HaveCount(50);
        DroppedFiles.UpTo(Drop(0), 50).Should().BeEmpty();

        var (first, count) = DroppedFiles.First(Drop(51));
        first!.Name.Should().Be("f0.txt");
        count.Should().Be(51);
        DroppedFiles.First(Drop(0)).Should().Be(((IBrowserFile?)null, 0));
    }
}
