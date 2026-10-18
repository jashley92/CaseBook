using System.Runtime.CompilerServices;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Common;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// CAP-32: the streamed CSV writer behind the audit and access-log exports: a byte-order mark, the rows up to the bound
/// with a cut said at the end, and C10's time limit, which stops a long export with a last line saying it's incomplete.
/// </summary>
public sealed class CsvStreamTests
{
    private static async IAsyncEnumerable<int> Numbers(int count, TimeSpan delay = default, [EnumeratorCancellation] CancellationToken ct = default)
    {
        for (var i = 1; i <= count; i++)
        {
            if (delay > TimeSpan.Zero) await Task.Delay(delay, ct);
            yield return i;
        }
    }

    private static Task<CsvStreamResult> Write(Stream output, IAsyncEnumerable<int> rows, int limit, TimeSpan timeLimit, CancellationToken ct = default) =>
        CsvStream.WriteAsync(output, rows, limit, sb => sb.Append("# head\r\nn\r\n"), (sb, n) => sb.Append(n).Append("\r\n"),
            (sb, cut) => { if (cut is { } c) sb.Append("# cut at ").Append(c).Append("\r\n"); }, timeLimit, ct);

    private static string Text(MemoryStream ms) => Encoding.UTF8.GetString(ms.ToArray());

    [Fact]
    public async Task Every_row_is_written_after_a_byte_order_mark_and_the_header()
    {
        using var ms = new MemoryStream();
        var result = await Write(ms, Numbers(20_000), 1_000_000, TimeSpan.FromMinutes(1));

        result.Should().Be(new CsvStreamResult(20_000, Truncated: false, TimedOut: false));
        ms.ToArray()[..3].Should().Equal(Encoding.UTF8.GetPreamble());
        var lines = Text(ms).TrimStart('﻿').Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        lines.Should().HaveCount(20_002);
        lines[2].Should().Be("1");
        lines[^1].Should().Be("20000");
    }

    [Fact]
    public async Task Rows_past_the_bound_are_cut_and_the_end_says_so()
    {
        using var ms = new MemoryStream();
        var result = await Write(ms, Numbers(10), 4, TimeSpan.FromMinutes(1));

        result.Should().Be(new CsvStreamResult(4, Truncated: true, TimedOut: false));
        Text(ms).Should().EndWith("4\r\n# cut at 4\r\n");
    }

    [Fact]
    public async Task An_export_past_its_time_limit_stops_and_says_the_file_is_incomplete()
    {
        using var ms = new MemoryStream();
        var result = await Write(ms, Numbers(1_000, TimeSpan.FromMilliseconds(20)), 1_000_000, TimeSpan.FromMilliseconds(300));

        result.TimedOut.Should().BeTrue();
        result.Rows.Should().BeLessThan(1_000);
        Text(ms).Should().EndWith($"# Stopped after {result.Rows} rows: the export ran past its time limit. This file is incomplete. Narrow the range and export again.\r\n");
    }

    [Fact]
    public async Task A_download_the_browser_cancels_is_not_reported_as_a_time_out()
    {
        using var ms = new MemoryStream();
        using var cancelled = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var act = () => Write(ms, Numbers(1_000, TimeSpan.FromMilliseconds(20)), 1_000_000, TimeSpan.FromMinutes(1), cancelled.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public void The_time_limit_grows_with_the_rows()
    {
        CsvStream.TimeLimit(0).Should().Be(TimeSpan.FromMinutes(15));
        CsvStream.TimeLimit(1_000_000).Should().Be(TimeSpan.FromMinutes(15) + TimeSpan.FromSeconds(1000));
    }
}
