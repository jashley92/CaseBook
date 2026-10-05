using FluentAssertions;
using IncidentManager.Application.Preferences;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>RD-24: the one keymap: what a key may be, the keys that stay fixed, and no key doing two things.</summary>
public sealed class KeymapTests
{
    [Theory]
    [InlineData("N", "n")]
    [InlineData("/", "/")]
    [InlineData("G   F", "g f")]
    [InlineData("ctrl + shift + f", "Ctrl+Shift+F")]
    [InlineData("alt+n", "Alt+N")]
    [InlineData("shift+n", null)]
    [InlineData("nn", null)]
    [InlineData("", null)]
    public void Bindings_are_normalized_or_refused(string raw, string? expected) =>
        Keymap.Normalize(raw).Should().Be(expected);

    [Fact]
    public void A_users_keys_are_validated_and_only_changes_are_kept()
    {
        var (s, problems) = Keymap.Validate(true, new Dictionary<string, string>
        {
            ["log"] = "Alt+L, l",
            ["task"] = "t",            // the default: not stored
            ["help"] = "",             // cleared
        });
        problems.Should().BeEmpty();
        s!.SingleKeysOff.Should().BeTrue();
        s.Keys.Should().BeEquivalentTo(new Dictionary<string, string> { ["log"] = "Alt+L, l", ["help"] = "" });
        Keymap.Deserialize(Keymap.Serialize(s.Keys)).Should().BeEquivalentTo(s.Keys);
    }

    [Fact]
    public void Fixed_keys_conflicts_and_a_bare_g_are_refused()
    {
        Keymap.Validate(false, new Dictionary<string, string> { ["log"] = "Ctrl+K" }).Problems.Should().ContainSingle(p => p.Contains("Ctrl+K"));
        Keymap.Validate(false, new Dictionary<string, string> { ["log"] = "t" }).Problems.Should().ContainSingle(p => p.Contains("used for both"));
        Keymap.Validate(false, new Dictionary<string, string> { ["log"] = "g" }).Problems.Should().NotBeEmpty();
        Keymap.Validate(false, new Dictionary<string, string> { ["nope"] = "x" }).Problems.Should().NotBeEmpty();
    }

    [Fact]
    public void The_defaults_have_no_conflicts() =>
        Keymap.Validate(false, new Dictionary<string, string>()).Problems.Should().BeEmpty();
}
