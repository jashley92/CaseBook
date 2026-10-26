using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// Third-party events have SLA targets of their own (<c>Sla:ThirdParty:*</c>), so every place that judges a case's clock
/// passes the case's origin: SlaPolicy.Evaluate, Breakdown and EvaluateDetection, PeriodSla.Judge, and a target looked up
/// with HoursFor. Left out, the origin defaults to internal and a vendor event is judged against the general target
/// (the team workload page did, written across two lines). A call that names no origin fails here.
/// </summary>
public sealed partial class SlaOriginGuardTests
{
    // Where a target is looked up without a case on purpose.
    private static readonly string[] Exempt =
    [
        "SlaPolicy.cs",     // the policy itself
        "SlaQueries.cs",    // looks each group up with its own origin
    ];

    [Fact]
    public void Every_SLA_judgement_passes_the_cases_origin()
    {
        var offenders = new List<string>();
        foreach (var file in Directory.EnumerateFiles(SrcRoot(), "*.*", SearchOption.AllDirectories)
                     .Where(f => (f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
                                 && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                                 && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                                 && !Exempt.Contains(Path.GetFileName(f))))
        {
            var text = File.ReadAllText(file);
            foreach (Match m in Judgement().Matches(text))
            {
                var args = Arguments(text, m.Index + m.Length);
                if (args.Contains("rigin", StringComparison.Ordinal)) continue;
                var line = text[..m.Index].Count(c => c == '\n') + 1;
                offenders.Add($"{Path.GetFileName(file)}:{line}: {Whitespace().Replace(m.Value + args, " ")}");
            }
        }

        offenders.Should().BeEmpty("a third-party event is judged against its own targets, so each judgement names the case's origin");
    }

    // The arguments of the call whose "(" ends at start, to its matching ")".
    private static string Arguments(string text, int start)
    {
        var depth = 1;
        for (var i = start; i < text.Length; i++)
        {
            if (text[i] == '(') depth++;
            else if (text[i] == ')' && --depth == 0) return text[start..i];
        }
        return text[start..];
    }

    [GeneratedRegex(@"(SlaPolicy\s*\.\s*(Evaluate|Breakdown|EvaluateDetection)|PeriodSla\s*\.\s*Judge|\.\s*HoursFor)\s*\(")]
    private static partial Regex Judgement();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();

    private static string SrcRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var src = Path.Combine(dir.FullName, "src");
            if (Directory.Exists(Path.Combine(src, "IncidentManager.Application"))) return src;
        }
        throw new DirectoryNotFoundException("src not found above the test output.");
    }
}
