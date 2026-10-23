using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-717: an API token's expiry is picked as a UTC day, so every list shows it as that UTC day. Converted to the viewer's
/// zone, a token picked for 3 Nov read "2 Nov" for anyone west of UTC, under a header that said UTC.
/// </summary>
public sealed partial class TokenExpiryDisplayTests
{
    [Theory]
    [InlineData("AdminApiTokens.razor")]
    [InlineData("AccountApiTokens.razor")]
    [InlineData("AdminRoles.razor")]
    [InlineData("AdminOffboarding.razor")]
    public void A_tokens_expiry_is_shown_as_its_utc_day(string page)
    {
        var markup = File.ReadAllText(Path.Combine(ComponentsRoot(), "Pages", page));
        var shown = ExpiryShown().Matches(markup).Select(m => m.Value).ToList();
        shown.Should().NotBeEmpty().And.OnlyContain(s => s == "@TimeDisplay.UtcDay(t.ExpiresAtUtc)");
        markup.Should().Contain("Expires (UTC)</th>");
        markup.Should().NotContain("Last used (UTC)</th>", "the last use is shown in the viewer's zone, with its label");
    }

    [GeneratedRegex(@"@[\w.]+\(t\.ExpiresAtUtc\)")]
    private static partial Regex ExpiryShown();
}
