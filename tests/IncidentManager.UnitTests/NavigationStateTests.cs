using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Cases;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// C15 (BUG-593, BUG-453/501's class): a bare <c>cases</c> link opens the user's default view (PROD-24), not the list
/// the link means, so every link into the case list names its filter (<see cref="CaseListLinks"/>). This reads the
/// sources and fails on a bare link outside the reviewed list below.
/// </summary>
public partial class NavigationStateTests
{
    // Files still holding a bare link, by file name, with why. Wave 2 decides the .razor ones (UI is wave 2's).
    private static readonly Dictionary<string, string> Reviewed = new(StringComparer.Ordinal)
    {
        // The Cases entry of the menus and the palette: "go to Cases" opens the default view by design (PROD-24).
        ["NavMenu.razor"] = "menu entry: the default view by design (PROD-24)",
        ["PhoneNav.razor"] = "menu entry: the default view by design (PROD-24)",
        ["CommandPalette.razor"] = "palette 'Cases' / 'c': the default view by design (PROD-24)",
        ["CaseListMemory.cs"] = "BUG-474: the back link with nothing remembered is the default view",
        // wave 2: a cancel / way back to the list; decide whether it should name a view.
        ["Error.razor"] = "wave 2",
        ["NotFoundPage.razor"] = "wave 2", ["ErrorFallback.razor"] = "wave 2",
        ["StyleGuide.razor"] = "wave 2 (a design sample)",
    };

    [Fact]
    public void No_link_into_the_case_list_is_bare()
    {
        var root = Path.Combine(RepoRoot(), "src");
        var offenders = new List<string>();
        foreach (var file in Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
                     .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
                     .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                                 && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)))
        {
            if (Reviewed.ContainsKey(Path.GetFileName(file))) continue;
            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                var t = line.TrimStart();
                if (t.StartsWith("//", StringComparison.Ordinal) || t.StartsWith("@*", StringComparison.Ordinal) || t.StartsWith("///", StringComparison.Ordinal)
                    || line.Contains("@page", StringComparison.Ordinal) || line.Contains("Equals(", StringComparison.Ordinal)
                    || line.Contains("GetUriWithQueryParameters", StringComparison.Ordinal) || line.Contains("paramref", StringComparison.Ordinal))
                    continue;
                if (BareLink().IsMatch(line)) offenders.Add($"{Path.GetRelativePath(root, file)}:{i + 1}");
            }
        }
        offenders.Should().BeEmpty("a link into the case list names its filter (CaseListLinks), since a bare 'cases' opens the default view");
    }

    [Fact]
    public void The_shared_links_name_their_filters()
    {
        CaseListLinks.NotificationDeadlines.Should().Be("cases?notify=true", "the at-risk filter takes in closed cases still owing a notice");
        CaseListLinks.OverdueTasks.Should().Be("cases?overdue=true&closed=true");
        CaseListLinks.QuietestFirst.Should().Be("cases?sort=updated&dir=asc");
        CaseListLinks.For("https://casebook.example/", CaseListLinks.NotificationDeadlines).Should().Be("https://casebook.example/cases?notify=true");
        CaseListLinks.For("", CaseListLinks.NotificationDeadlines).Should().BeNull("no base URL configured: no link");
        new[] { CaseListLinks.NotificationDeadlines, CaseListLinks.OverdueTasks, CaseListLinks.QuietestFirst }
            .Should().OnlyContain(l => l.StartsWith("cases?", StringComparison.Ordinal));
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }

    // "cases", "/cases", or an interpolated "...{BaseUrl}/cases" with nothing after it; not the word in a count ("case" : "cases").
    [GeneratedRegex(@"(?<!""case""\s*:\s*)""(?:[^""]*\})?/?cases""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex BareLink();
}
