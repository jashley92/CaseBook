using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Access;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Access;
using IncidentManager.Infrastructure.Compliance;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-592 (C16): <c>Enum.TryParse</c> / <c>Enum.Parse</c> read a number ("4", "-1", "+7", undefined ones too) and a
/// comma list ("A,B", OR-ed into another member), so a gate trigger "Closing,Reopen" became another transition and a
/// template classification "7" was stored. Text from a store, a setting, a link or a bundle is read with
/// <c>EnumNames.TryParse</c> (names only). This scan fails on any other call in src, so a new one can't come back.
/// </summary>
public partial class EnumParsingTests
{
    // Sites not fixed in this wave, each with its reason. A count, so a second call in a listed file still fails.
    private static readonly Dictionary<string, int> Allowed = new(StringComparer.Ordinal)
    {
        // Wave 2: files outside this wave's list (reported). Each reads text the app itself wrote, or startup config.
        ["IncidentManager.Domain/Entities/Role.cs"] = 1,                       // letters only and IsDefined (WF-45)
        ["IncidentManager.Application/Mitre/AttackCatalog.cs"] = 1,            // the embedded ATT&CK catalog
        ["IncidentManager.Infrastructure/Security/CertificateLookup.cs"] = 1,  // Integrity:SigningKey:StoreLocation
        ["IncidentManager.Infrastructure/Security/RsaSealSigner.cs"] = 1,      // the same setting, checked by CertificateLookup first
        ["IncidentManager.Web/Security/CurrentUser.cs"] = 1,                   // permission claims the app issued by name
        ["IncidentManager.Web/Security/PagePolicies.cs"] = 1,                  // [Authorize] policy constants
    };

    [Fact]
    public void Text_is_read_into_an_enum_by_name_only()
    {
        var found = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        var root = Path.Combine(RepoRoot(), "src");
        foreach (var path in Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
                     .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal)))
        {
            var file = Path.GetRelativePath(root, path).Replace('\\', '/');
            if (file.Contains("/obj/", StringComparison.Ordinal) || file.Contains("/bin/", StringComparison.Ordinal)) continue;
            if (file == "IncidentManager.Domain/Common/EnumNames.cs") continue;   // the one place that may
            var lines = File.ReadAllLines(path);
            for (var i = 0; i < lines.Length; i++)
                if (RawParse().IsMatch(LineComment().Replace(lines[i], "")))
                    (found.TryGetValue(file, out var at) ? at : found[file] = []).Add(i + 1);
        }

        var offenders = found
            .Where(f => f.Value.Count > Allowed.GetValueOrDefault(f.Key))
            .SelectMany(f => f.Value.Select(line => $"{f.Key}:{line}"))
            .ToList();
        offenders.Should().BeEmpty("text goes through EnumNames.TryParse, which takes a declared name only");

        // An allow-list entry that's no longer needed is taken out, so the list stays the true remainder.
        var stale = Allowed.Where(a => found.GetValueOrDefault(a.Key)?.Count != a.Value).Select(a => a.Key).ToList();
        stale.Should().BeEmpty("a fixed site comes off the wave-2 list (or its count is corrected)");
    }

    [Theory]
    [InlineData("3")]
    [InlineData("99")]
    [InlineData("-1")]
    [InlineData("+3")]
    [InlineData("EscalateToIncident,EscalateToBreach")]   // OR-ed, this is CloseCase
    [InlineData("EscalateToIncident, EscalateToBreach")]
    [InlineData("")]
    [InlineData(null)]
    public void A_number_or_a_list_is_not_a_name(string? raw)
    {
        EnumNames.TryParse<StageGateTrigger>(raw, out _).Should().BeFalse();
        EnumNames.OrNull<StageGateTrigger>(raw, ignoreCase: true).Should().BeNull();
    }

    [Fact]
    public void A_name_is_read_trimmed_and_by_the_case_asked_for()
    {
        EnumNames.TryParse<StageGateTrigger>(" CloseCase ", out var t).Should().BeTrue();
        t.Should().Be(StageGateTrigger.CloseCase);
        EnumNames.TryParse<StageGateTrigger>("closecase", out _).Should().BeFalse("case-sensitive unless asked");
        EnumNames.OrNull<StageGateTrigger>("closecase", ignoreCase: true).Should().Be(StageGateTrigger.CloseCase);
        EnumNames.TryParseExact<StageGateTrigger>(" CloseCase", out _).Should().BeFalse("exact: a padded name isn't one");
    }

    [Fact]
    public void A_numeric_layout_token_is_not_a_section(/* BUG-592, C2 */)
    {
        // "3" read as EventTimeline (switched on, first), "99" as nothing; the layout now ignores both like any unknown token.
        ReportLayout.Parse("3,!Summary").Select(s => s.Section).First().Should().Be(ReportSection.Summary);
        ReportLayout.Resolve("!Summary,99").Should().NotContain(ReportSection.Summary).And.OnlyContain(s => Enum.IsDefined(s));
    }

    [Theory]
    [InlineData("5", AccessLogScope.All)]
    [InlineData("0,1", AccessLogScope.All)]
    [InlineData(" off ", AccessLogScope.Off)]
    public void A_configured_scope_is_read_by_name(string raw, AccessLogScope expected)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Access:LogScope"] = raw }).Build();
        new ConfigurationAccessLogPolicy(config).Scope.Should().Be(expected);
    }

    [Theory]
    [InlineData("5", NotificationStartBasis.Determination)]
    [InlineData(" detection ", NotificationStartBasis.Detection)]
    public void A_configured_start_basis_is_read_by_name(string raw, NotificationStartBasis expected)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Compliance:NotificationDeadlines:StartBasis"] = raw }).Build();
        new ConfigurationNotificationDeadlineSettingsProvider(config).Current.StartBasis.Should().Be(expected);
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }

    [GeneratedRegex(@"\bEnum\s*\.\s*(?:TryParse|Parse)\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex RawParse();

    // A line comment (not the "//" of a URL), so a comment that names Enum.TryParse doesn't count.
    [GeneratedRegex(@"(?<!:)//.*$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex LineComment();
}
