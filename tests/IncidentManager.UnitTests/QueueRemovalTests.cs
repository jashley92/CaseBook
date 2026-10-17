using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// C20 (BUG-617): work queued for later (held mail, outbox rows, report jobs, SIEM lanes) is taken off its queue only
/// after it went, or was given up with a record, never before the attempt. The held-mail drain dequeued an email and
/// then sent it, so one the relay still didn't take was lost. Every place in src that takes an item off a queue (an
/// in-memory Queue or Channel, or a delete from a queue table) is listed below: either the attempt must come before the
/// removal in the same method, or the entry says why the site is safe. A new removal site fails the test until it's
/// listed. The attempt must also be on every way to the removal (BUG-651: a send made only while email was on, then a
/// delete either way, emptied the queue). What this can't see: a removal reached through a helper method (the drain deletes inline for that reason),
/// or an attempt whose outcome is ignored; the behaviour tests (EmailSenderHeldMailTests, CriticalAlertOutboxTests)
/// cover those for the mail queues. Notification marks aren't queued work (removing one makes a reminder go again).
/// </summary>
public sealed partial class QueueRemovalTests
{
    // Taking an item off: Queue.Dequeue/TryDequeue, a collection's TryTake, a channel read, or a delete from a queue table.
    [GeneratedRegex(@"\.(?:Try)?Dequeue\(|\.TryTake\(|\.Reader\.(?:TryRead|ReadAsync|ReadAllAsync)\(|\b(?:HeldEmails|AlertDeliveries)\b[^;]*?\.(?:Remove|RemoveRange|ExecuteDelete|ExecuteDeleteAsync)\(",
        RegexOptions.None, 1000)]
    private static partial Regex Removal();

    /// <summary>A removal site: the file, the method it's in, and either the attempt that must come first or why it's safe.</summary>
    private sealed record Site(string File, string Method, string? AttemptFirst, string? Why);

    private static readonly Site[] Sites =
    [
        new("Infrastructure/Notifications/EmailSender.cs", "DrainHeldAsync", "DeliverHeldAsync(", null),
        new("Infrastructure/Notifications/OutboundCircuit.cs", "Failed", null,
            "failure times aging out of the back-off window, not queued work"),
        new("Web/BackgroundJobs/SecurityEventDispatcher.cs", "Add", null,
            "a full lane drops its oldest event of that kind and counts it (Dropped), which the worker logs"),
        new("Web/BackgroundJobs/SecurityEventDispatcher.cs", "TakeAsync", null,
            "SIEM is best effort: the worker sends each event it takes, and one a transport throws on is logged by event id"),
        new("Web/BackgroundJobs/SecurityEventDispatcher.cs", "ExecuteAsync", null,
            "moves each event from the sink's channel into every lane; nothing is sent here"),
        new("Web/BackgroundJobs/ReportJobs.cs", "ExecuteAsync", null,
            "each job runs as it's read, and a failure is kept on the job (Failed, with the reason) for the person who asked"),
    ];

    [Theory]
    [InlineData("lock (_held) _held.Dequeue();", true)]
    [InlineData("await foreach (var x in _queue.Reader.ReadAllAsync(ct))", true)]
    [InlineData("await db.HeldEmails.Where(h => h.Id == id).ExecuteDeleteAsync();", true)]
    [InlineData("db.AlertDeliveries.Remove(row);", true)]
    [InlineData("db.AlertDeliveries.Add(row);", false)]
    [InlineData("db.PinnedCases.Where(p => p.UserId == me).ExecuteDeleteAsync(ct);", false)]
    public void The_scan_sees_a_removal(string line, bool flagged) => Removal().IsMatch(line).Should().Be(flagged);

    [Fact]
    public void Queued_work_is_removed_only_after_its_attempt_or_where_reviewed()
    {
        var src = Path.Combine(ComponentSourceScanner.RepoRoot(), "src");
        var offenders = new List<string>();
        var used = new HashSet<Site>();
        foreach (var path in Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
                     .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}")
                         && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")))
        {
            var code = ComponentSourceScanner.Strip(File.ReadAllText(path));
            var file = Path.GetRelativePath(src, path).Replace('\\', '/');
            if (file.StartsWith("IncidentManager.", StringComparison.Ordinal)) file = file["IncidentManager.".Length..];
            var methods = ComponentSourceScanner.Methods(code).ToList();
            foreach (Match m in Removal().Matches(code))
            {
                var line = code.AsSpan(0, m.Index).Count('\n') + 1;
                // The innermost method around it.
                var method = methods.Where(x => x.Start <= m.Index && m.Index < x.Start + x.Body.Length).MinBy(x => x.Body.Length);
                var site = Sites.FirstOrDefault(s => file.EndsWith(s.File, StringComparison.Ordinal) && s.Method == method?.Name);
                if (site is null)
                {
                    offenders.Add($"{file}:{line} in {method?.Name ?? "(no method)"}: not listed");
                    continue;
                }
                used.Add(site);
                if (site.AttemptFirst is { } attempt && method is not null)
                {
                    var tried = method.Body.IndexOf(attempt, StringComparison.Ordinal);
                    if (tried < 0 || method.Start + tried > m.Index)
                        offenders.Add($"{file}:{line} in {method.Name}: removed before {attempt.TrimEnd('(')} tries it");
                    else if (!AlwaysTriedBefore(method.Body, tried, m.Index - method.Start))
                        offenders.Add($"{file}:{line} in {method.Name}: removed on a path that skips {attempt.TrimEnd('(')}");
                }
            }
        }

        offenders.Should().BeEmpty("queued work comes off its queue only after it went or was given up with a record");
        Sites.Except(used).Select(s => $"{s.File} {s.Method}").Should().BeEmpty("the list names only sites that still remove something");
    }

    /// <summary>
    /// BUG-651: the attempt before the removal must be on every way to it: a statement of its own (not one arm of a ?:,
    /// or under an if without braces), in the removal's block or one around it. The drain sent only while email was on
    /// (<c>o.Enabled ? await DeliverLoggedAsync(...) : null</c>) and deleted either way, so email off emptied the queue.
    /// </summary>
    private static bool AlwaysTriedBefore(string body, int attempt, int removal)
    {
        var start = body.LastIndexOfAny([';', '{', '}'], attempt) + 1;
        if (!StatementLead().IsMatch(body[start..attempt])) return false;
        var depth = 0;
        for (var i = attempt; i < removal; i++)
        {
            if (body[i] == '{') depth++;
            else if (body[i] == '}' && --depth < 0) return false;   // the attempt's block closed first: it was conditional
        }
        return true;
    }

    // What may lead a statement up to its call: an assignment to a new or existing variable, and await.
    [GeneratedRegex(@"^\s*(?:(?:[\w.<>]+\??\s+)?\w+\s*=\s*)?(?:await\s+)?$", RegexOptions.None, 1000)]
    private static partial Regex StatementLead();

    [Theory]
    [InlineData("{ var outcome = await Try(x); if (outcome == A) return; await db.HeldEmails.ExecuteDeleteAsync(); }", true)]
    [InlineData("{ SendOutcome? outcome = on\n ? await Try(x)\n : null; await db.HeldEmails.ExecuteDeleteAsync(); }", false)]
    [InlineData("{ if (on) outcome = await Try(x); await db.HeldEmails.ExecuteDeleteAsync(); }", false)]
    [InlineData("{ if (on) { var outcome = await Try(x); } await db.HeldEmails.ExecuteDeleteAsync(); }", false)]
    [InlineData("{ var outcome = await Try(x); if (outcome == A) { await db.HeldEmails.ExecuteDeleteAsync(); } }", true)]
    public void The_attempt_must_be_on_every_way_to_the_removal(string body, bool safe) =>
        AlwaysTriedBefore(body, body.IndexOf("Try(", StringComparison.Ordinal), body.IndexOf("db.HeldEmails", StringComparison.Ordinal))
            .Should().Be(safe);

    // BUG-627: the methods that keep a failed send for later write it without the caller's token, which may be the very
    // reason the send failed (a request that ended, a shutdown). Reads may stop with the caller: nothing is lost.
    [Theory]
    [InlineData("Infrastructure/Notifications/CriticalAlertOutbox.cs", "SendAsync")]
    [InlineData("Infrastructure/Notifications/EmailSender.cs", "HoldAsync")]
    public void Queued_work_is_kept_without_the_callers_token(string file, string method)
    {
        var code = ComponentSourceScanner.Strip(File.ReadAllText(Path.Combine(ComponentSourceScanner.RepoRoot(), "src",
            "IncidentManager." + file.Replace('/', Path.DirectorySeparatorChar))));
        var bodies = ComponentSourceScanner.Methods(code).Where(m => m.Name == method || m.Name == method + "<lambda>").ToList();
        bodies.Should().NotBeEmpty($"{file} still has {method}");
        bodies.SelectMany(m => CallerToken().Matches(m.Body).Select(x => $"{file} {m.Name}: {x.Value}"))
            .Should().BeEmpty("a cancelled caller mustn't stop the failed send being kept");
    }

    // A database call given a token that isn't CancellationToken.None.
    [GeneratedRegex(@"(?:SaveChangesAsync|CreateDbContextAsync|CountAsync|AddAsync)\((?!\s*CancellationToken\.None\s*\))[^()]*\bct\b",
        RegexOptions.None, 1000)]
    private static partial Regex CallerToken();
}
