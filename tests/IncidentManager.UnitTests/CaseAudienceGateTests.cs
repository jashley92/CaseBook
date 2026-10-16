using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// C14 (BUG-596/597, BUG-377's class): everything CaseService reads or sends about a case is held to the case's audience.
/// A read of the Cases set goes through need-to-know scoping (Scoped / ForUser) unless it is on the reviewed list below,
/// and a notification that names a person is sent only to the people <c>ReminderAudience.RecipientsAsync</c> lets
/// through (active in the directory of record, a role granting ViewCases, able to see a restricted case). These checks
/// read CaseService's source, so a new unscoped read or an unfiltered notification fails here.
/// </summary>
public partial class CaseAudienceGateTests
{
    // Unscoped reads that are safe, by enclosing method, with why.
    private static readonly Dictionary<string, string> UnscopedReads = new(StringComparer.Ordinal)
    {
        ["NumberTakenAsync"] = "a case number is unique across every case, seen or not (BUG-145); only a bool comes back",
        ["SearchMatchesAsync"] = "the ids come from the page of an already scoped list",
        ["RefreshPartsAsync"] = "after the scoped AnyAsync check for the same id",
        ["CasesShowingAsync"] = "the ids come from an already scoped search",
        ["ClosingLinesAsync"] = "the ids come from already scoped cases",
        ["IsExerciseAsync"] = "a bool for a case the caller has already loaded through scoping",
        ["EnsureSameSideAsync"] = "a bool for two cases the caller has already loaded through scoping",
        ["SearchLinkableCasesAsync"] = "the case's own exercise flag; the cases offered are read through Scoped",
    };

    // Notifications that don't go to a case's audience, with why.
    private static readonly Dictionary<string, string> NotAudience = new(StringComparer.Ordinal)
    {
        ["OnReclassifiedAsync"] = "goes to the configured Legal distribution and the shared channel, not to a person on the case",
    };

    [Fact]
    public void Every_read_of_the_cases_set_is_scoped_or_reviewed()
    {
        var (lines, methods) = Source();
        var offenders = new List<string>();
        for (var i = 0; i < lines.Length; i++)
        {
            foreach (Match m in CasesRead().Matches(lines[i]))
            {
                var before = lines[i][..m.Index];
                if (before.EndsWith("Scoped(", StringComparison.Ordinal) || lines[i].Contains(".ForUser(", StringComparison.Ordinal)) continue;
                if (lines[i][(m.Index + m.Length)..].TrimStart().StartsWith(".Add(", StringComparison.Ordinal)) continue;   // a write
                var method = Enclosing(methods, i);
                if (!UnscopedReads.ContainsKey(method)) offenders.Add($"CaseService.cs:{i + 1} {method}");
            }
        }
        offenders.Should().BeEmpty("a read of db.Cases goes through Scoped()/ForUser, or is reviewed on the list above");
    }

    [Fact]
    public void Every_notification_to_a_person_is_preceded_by_the_audience_filter()
    {
        var (lines, methods) = Source();
        var offenders = new List<string>();
        var seen = 0;
        for (var i = 0; i < lines.Length; i++)
        {
            foreach (Match m in NotificationCall().Matches(lines[i]))
            {
                seen++;
                if (NotAudience.ContainsKey(m.Groups["name"].Value)) continue;
                var start = methods.Where(x => x.Line <= i).Select(x => x.Line).DefaultIfEmpty(0).Max();
                var body = string.Join('\n', lines[start..(i + 1)]);
                var call = body.LastIndexOf(m.Value, StringComparison.Ordinal);
                if (!body[..call].Contains("RecipientsAsync(", StringComparison.Ordinal))
                    offenders.Add($"CaseService.cs:{i + 1} {Enclosing(methods, i)} -> {m.Groups["name"].Value}");
            }
        }
        seen.Should().BeGreaterThan(3, "the scan must find CaseService's notification calls");
        offenders.Should().BeEmpty("a notification naming a person goes only to the recipients RecipientsAsync lets through");
    }

    [Fact]
    public void The_audience_filter_is_registered_for_injection()
    {
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        IncidentManager.Application.DependencyInjection.AddApplication(services);
        services.Should().Contain(d => d.ServiceType == typeof(IncidentManager.Application.Notifications.ReminderAudience),
            "CaseService takes the shared filter from DI, so it asks the directory of record (ITokenOwnerCheck)");
    }

    private static string Enclosing(List<(int Line, string Name)> methods, int line) =>
        methods.Where(m => m.Line <= line).Select(m => m.Name).LastOrDefault() ?? "?";

    private static (string[] Lines, List<(int Line, string Name)> Methods) Source()
    {
        var path = Path.Combine(RepoRoot(), "src", "IncidentManager.Application", "Cases", "CaseService.cs");
        var lines = File.ReadAllLines(path);
        var methods = new List<(int, string)>();
        for (var i = 0; i < lines.Length; i++)
            if (MethodStart().Match(lines[i]) is { Success: true } m) methods.Add((i, m.Groups["name"].Value));
        return (lines, methods);
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }

    [GeneratedRegex(@"^    (?:public|private|internal|protected)\b[^=;(]*?\s(?<name>\w+)(?:<[^>]*>)?\s*\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex MethodStart();

    [GeneratedRegex(@"\bdb\.Cases\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex CasesRead();

    [GeneratedRegex(@"_notifications\.(?<name>On\w+Async)\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex NotificationCall();
}
