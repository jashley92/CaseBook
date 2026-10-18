using System.Globalization;
using System.Text;

namespace IncidentManager.Application.Common;

/// <summary>CAP-32: how a streamed CSV ended: the rows written, whether it was cut at its bound, and whether it ran past
/// its time limit (the file is then incomplete, says so on its last line, and the caller aborts the response).</summary>
public sealed record CsvStreamResult(int Rows, bool Truncated, bool TimedOut);

/// <summary>
/// CAP-32: writes a CSV to a response as its rows are read, as the compliance bundle streams its chain, so an export holds
/// a large range without building it in memory. The rows come from one statement read as it goes; the text is
/// UTF-8 with a byte-order mark (so Excel reads it as UTF-8, as every CSV download does) and goes out every
/// <see cref="FlushChars"/> characters. A bound stays, raised to what a spreadsheet can open (<see cref="MaxRows"/>): a cut
/// says so at the top (when the count read first says it will be cut) and at the end. C10: a time limit
/// (<see cref="TimeLimit"/>) stops one that runs too long, a slow reader's included, with a last line saying the file is
/// incomplete; the caller aborts the response so the browser shows the download as failed.
/// </summary>
public static class CsvStream
{
    /// <summary>The most rows one export holds: an Excel sheet's 1,048,576 rows, less room for the comment lines.</summary>
    public const int MaxRows = 1_000_000;

    /// <summary>Characters gathered before each write to the response.</summary>
    internal const int FlushChars = 64 * 1024;

    /// <summary>A quarter of an hour, plus a second for each 1,000 rows (as the evidence package, CAP-12, bounds itself).</summary>
    public static TimeSpan TimeLimit(int rows) => TimeSpan.FromMinutes(15) + TimeSpan.FromSeconds(Math.Max(0, rows) / 1000d);

    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>
    /// Writes <paramref name="header"/>, then each of <paramref name="rows"/> up to <paramref name="limit"/>, then
    /// <paramref name="tail"/> (given the limit when the rows went past it, else null). Reading one row past the limit is
    /// how a cut is known at the end. <paramref name="timeLimit"/> bounds the whole of it.
    /// </summary>
    public static async Task<CsvStreamResult> WriteAsync<T>(Stream output, IAsyncEnumerable<T> rows, int limit,
        Action<StringBuilder> header, Action<StringBuilder, T> row, Action<StringBuilder, int?> tail, TimeSpan timeLimit,
        CancellationToken ct)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bounded.CancelAfter(timeLimit);
        var sb = new StringBuilder(FlushChars + 4096);
        var written = 0;
        var truncated = false;
        try
        {
            await output.WriteAsync(Encoding.UTF8.GetPreamble(), bounded.Token);
            header(sb);
            await foreach (var r in rows.WithCancellation(bounded.Token))
            {
                if (written == limit) { truncated = true; break; }
                row(sb, r);
                written++;
                if (sb.Length >= FlushChars) await SendAsync(output, sb, bounded.Token);
            }
            tail(sb, truncated ? limit : null);
            await SendAsync(output, sb, bounded.Token);
            await output.FlushAsync(bounded.Token);
            return new CsvStreamResult(written, truncated, TimedOut: false);
        }
        catch (OperationCanceledException) when (bounded.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            // Past the time limit: say so where a reader stops, if the connection still takes it (briefly), and let the
            // caller abort the response. No comma or semicolon in the line (BUG-516, BUG-543): it stays one cell.
            sb.Clear().Append(string.Create(CultureInfo.InvariantCulture,
                $"\r\n# Stopped after {written} rows: the export ran past its time limit. This file is incomplete. Narrow the range and export again.\r\n"));
            using var last = CancellationTokenSource.CreateLinkedTokenSource(ct);
            last.CancelAfter(TimeSpan.FromSeconds(5));
            try { await SendAsync(output, sb, last.Token); await output.FlushAsync(last.Token); }
            catch (Exception e) when (e is OperationCanceledException or IOException) { /* the connection is gone or stuck */ }
            return new CsvStreamResult(written, truncated, TimedOut: true);
        }
    }

    private static async Task SendAsync(Stream output, StringBuilder sb, CancellationToken ct)
    {
        if (sb.Length == 0) return;
        await output.WriteAsync(Utf8.GetBytes(sb.ToString()), ct);
        sb.Clear();
    }
}
