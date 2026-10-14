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
    [InlineData("ctrl+f5", "Ctrl+F5")]               // BUG-355: as the dispatcher names it
    [InlineData("ctrl+shift+f12", "Ctrl+Shift+F12")]
    [InlineData("Ctrl+Shift+1", null)]               // the browser reports "!", never Shift+1
    [InlineData("alt+shift+/", null)]
    [InlineData("Ctrl+1", "Ctrl+1")]
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

    [Theory]
    [InlineData(";")]
    [InlineData(",")]
    [InlineData("Ctrl+;")]
    [InlineData("Alt+,")]
    [InlineData("/, ,")]
    [InlineData(", n")]
    public void The_stored_forms_separators_are_refused_as_keys(string raw /* BUG-402 */)
    {
        var (settings, problems) = Keymap.Validate(false, new Dictionary<string, string> { ["log"] = raw });
        settings.Should().BeNull("the binding would be lost or clear the shortcut once stored");
        problems.Should().ContainSingle(p => p.Contains("can't be shortcut keys"));
    }

    [Fact]
    public void A_trailing_comma_is_still_just_a_separator() =>
        Keymap.Validate(false, new Dictionary<string, string> { ["log"] = "Alt+L," }).Settings!.Keys["log"].Should().Be("Alt+L");

    [Theory]
    [InlineData("Ctrl+Shift+K")]
    [InlineData("Ctrl+Alt+K")]
    public void Ctrl_chords_on_K_are_refused_because_the_command_bar_takes_them(string raw /* BUG-402 */) =>
        Keymap.Validate(false, new Dictionary<string, string> { ["log"] = raw }).Problems.Should().ContainSingle(p => p.Contains("command bar"));

    [Fact]
    public void Alt_K_is_still_allowed() =>
        Keymap.Validate(false, new Dictionary<string, string> { ["log"] = "Alt+K" }).Problems.Should().BeEmpty();

    [Fact]
    public void The_defaults_have_no_conflicts() =>
        Keymap.Validate(false, new Dictionary<string, string>()).Problems.Should().BeEmpty();
}
