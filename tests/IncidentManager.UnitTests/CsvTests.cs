using FluentAssertions;
using IncidentManager.Application.Common;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// The shared CSV encoder (S-01): RFC-4180 quoting plus spreadsheet formula-injection (CSV / DDE)
/// neutralisation. Every export routes fields through <see cref="Csv.Escape"/>.
/// </summary>
public class CsvTests
{
    [Theory]
    // Plain data passes through untouched.
    [InlineData("plain text", "plain text")]
    [InlineData("2026-05_FS_01", "2026-05_FS_01")]   // a case number (leads with a digit)
    [InlineData("", "")]
    // Formula/DDE leaders are neutralised with a leading apostrophe.
    [InlineData("=1+1", "'=1+1")]
    [InlineData("=cmd|' /c calc'!A1", "'=cmd|' /c calc'!A1")]
    [InlineData("@SUM(A1:A9)", "'@SUM(A1:A9)")]
    [InlineData("+1+1", "'+1+1")]                     // '+' not leading a plain number
    [InlineData("-1+1", "'-1+1")]                     // '-' not leading a plain number
    [InlineData("=", "'=")]
    // Genuine signed numbers stay numeric — not turned into text.
    [InlineData("-5", "-5")]
    [InlineData("+5", "+5")]
    [InlineData("-5.5", "-5.5")]
    public void Escapes_formula_leaders_but_leaves_real_numbers(string input, string expected)
        => Csv.Escape(input).Should().Be(expected);

    [Fact]
    public void Null_becomes_empty()
        => Csv.Escape(null).Should().BeEmpty();

    [Fact]
    public void A_comma_triggers_rfc4180_quoting()
        => Csv.Escape("a,b").Should().Be("\"a,b\"");

    [Fact]
    public void Embedded_quotes_are_doubled_and_the_field_quoted()
        => Csv.Escape("say \"hi\"").Should().Be("\"say \"\"hi\"\"\"");

    [Fact]
    public void A_formula_leader_and_a_comma_are_both_handled()
        => Csv.Escape("=1,2").Should().Be("\"'=1,2\"");   // guarded first, then quoted for the comma

    [Fact]
    public void A_tab_leader_is_guarded()
        => Csv.Escape("\t=1").Should().Be("'\t=1");        // tab isn't a quote trigger, so no quoting

    [Fact]
    public void A_carriage_return_leader_is_guarded_and_quoted()
        => Csv.Escape("\r=1").Should().Be("\"'\r=1\"");    // CR is both a leader and a quote trigger
}
