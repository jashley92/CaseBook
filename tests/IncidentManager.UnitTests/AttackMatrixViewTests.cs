using IncidentManager.Application.Mitre;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>The ATT&amp;CK picker's columns for a filter: only tactics with a match while filtering, every tactic otherwise.</summary>
public class AttackMatrixViewTests
{
    private static AttackTechnique T(string id, string name, params MitreTactic[] tactics) => new(id, name, tactics, id.Contains('.'));

    // Execution has T1059 (with a PowerShell sub-technique), Credential Access has T1003 and T1110, and T1110 is also in
    // Discovery only through a sub-technique there.
    private static readonly IReadOnlyList<AttackMatrixColumn> Small = AttackMatrixView.Build(
    [
        T("T1059", "Command and Scripting Interpreter", MitreTactic.Execution),
        T("T1059.001", "PowerShell", MitreTactic.Execution),
        T("T1003", "OS Credential Dumping", MitreTactic.CredentialAccess),
        T("T1110", "Brute Force", MitreTactic.CredentialAccess),
        T("T1110.001", "Password Guessing", MitreTactic.CredentialAccess, MitreTactic.Discovery),
    ]);

    private static readonly int AllTactics = AttackMatrixView.Tactics.Count;

    private static MitreTactic[] Visible(AttackMatrixView v) => v.Columns.Where(c => !c.Hidden).Select(c => c.Tactic).ToArray();

    [Fact]
    public void The_matrix_has_every_tactic_in_order_and_a_heading_for_a_parent_listed_only_for_its_subs()
    {
        Assert.Equal(15, AllTactics);
        Assert.Equal(MitreTactic.Reconnaissance, AttackMatrixView.Tactics[0]);
        Assert.Equal(MitreTactic.Impact, AttackMatrixView.Tactics[^1]);
        Assert.Equal(AttackMatrixView.Tactics, Small.Select(c => c.Tactic));
        var row = Assert.Single(Small.Single(c => c.Tactic == MitreTactic.Discovery).Rows);
        Assert.Equal("T1110", row.Parent.Id);
        Assert.False(row.ParentInTactic);
        Assert.Single(row.Subs);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void An_empty_filter_shows_every_tactic_with_no_counts_line(string? filter)
    {
        var v = AttackMatrixView.For(Small, filter);
        Assert.False(v.IsFiltering);
        Assert.All(v.Columns, c => Assert.False(c.Hidden));
        Assert.Equal(AllTactics, v.VisibleTactics);
        Assert.Null(v.Summary);
        Assert.Null(v.NoMatchText);
        Assert.False(v.NoMatches);
    }

    [Fact]
    public void A_filter_hides_the_tactics_without_a_match_and_keeps_the_others_in_order()
    {
        var v = AttackMatrixView.For(Small, "cred");
        Assert.Equal([MitreTactic.CredentialAccess], Visible(v));
        Assert.Equal(AllTactics, v.Columns.Count); // a hidden column stays in the layout, to fold away
        Assert.Equal(["T1003"], v.Columns.Single(c => !c.Hidden).Rows.Select(r => r.Row.Parent.Id));

        Assert.Equal([MitreTactic.Execution, MitreTactic.CredentialAccess, MitreTactic.Discovery], Visible(AttackMatrixView.For(Small, "T1")));
    }

    [Fact]
    public void Matching_is_on_id_or_name_ignoring_case()
    {
        Assert.Equal([MitreTactic.Execution], Visible(AttackMatrixView.For(Small, "t1059")));
        Assert.Equal([MitreTactic.CredentialAccess], Visible(AttackMatrixView.For(Small, "DUMPING")));
        Assert.True(AttackCatalog.Matches(T("T1", "x"), ""));
    }

    [Fact]
    public void The_counts_line_names_the_tactics_shown_and_the_distinct_techniques_matched()
    {
        // T1110.001 is under both Credential Access and Discovery: one technique, counted once.
        Assert.Equal($"Showing 2 of {AllTactics} tactics with matches · 1 technique", AttackMatrixView.For(Small, "guess").Summary);
        Assert.Equal($"Showing 3 of {AllTactics} tactics with matches · 5 techniques", AttackMatrixView.For(Small, "T1").Summary);
    }

    [Fact]
    public void No_match_says_so_instead_of_an_empty_matrix()
    {
        var v = AttackMatrixView.For(Small, "  zzqx ");
        Assert.True(v.NoMatches);
        Assert.Equal("zzqx", v.Filter);
        Assert.Equal("No techniques match 'zzqx'", v.NoMatchText);
        Assert.Null(v.Summary);
        Assert.All(v.Columns, c => Assert.True(c.Hidden));
        Assert.Equal("", v.Layout);
    }

    [Fact]
    public void A_sub_technique_match_opens_its_parent_to_just_the_matching_subs()
    {
        var v = AttackMatrixView.For(Small, "powershell");
        Assert.Equal([MitreTactic.Execution], Visible(v));
        var row = Assert.Single(v.Columns.Single(c => !c.Hidden).Rows);
        Assert.Equal("T1059", row.Row.Parent.Id);
        Assert.True(row.OpenForMatch);
        Assert.Equal(["T1059.001"], row.ShownSubs.Select(s => s.Id));

        // A parent that matches itself lists all its subs when opened, and isn't opened for them.
        var parent = AttackMatrixView.For(Small, "interpreter").Columns.Single(c => !c.Hidden).Rows.Single();
        Assert.False(parent.OpenForMatch);
        Assert.Single(parent.ShownSubs);
    }

    [Fact]
    public void A_column_that_just_lost_its_matches_keeps_its_rows_for_that_change_only()
    {
        var all = AttackMatrixView.For(Small, "");
        var cred = AttackMatrixView.For(Small, "cred", all);
        var leaving = cred.Columns.Single(c => c.Tactic == MitreTactic.Execution);
        Assert.True(leaving.Hidden);
        Assert.Equal(["T1059"], leaving.Rows.Select(r => r.Row.Parent.Id));

        Assert.Empty(AttackMatrixView.For(Small, "credx", cred).Columns.Single(c => c.Tactic == MitreTactic.Execution).Rows);
        // A column never shown before has nothing to fade.
        Assert.Empty(cred.Columns.Single(c => c.Tactic == MitreTactic.Impact).Rows);
    }

    [Fact]
    public void Layout_changes_only_when_the_columns_shown_change()
    {
        Assert.Equal(AttackMatrixView.For(Small, "cred").Layout, AttackMatrixView.For(Small, "credential").Layout);
        Assert.NotEqual(AttackMatrixView.For(Small, "cred").Layout, AttackMatrixView.For(Small, "").Layout);
    }

    [Fact]
    public void Against_the_catalogue_T1059_and_powershell_keep_execution()
    {
        Assert.Same(AttackMatrixView.Matrix, AttackMatrixView.Matrix);
        Assert.Same(AttackMatrixView.Unfiltered, AttackMatrixView.For("  "));
        var t1059 = AttackMatrixView.For("T1059");
        Assert.Contains(MitreTactic.Execution, Visible(t1059));
        Assert.StartsWith("Showing ", t1059.Summary);

        var exec = AttackMatrixView.For("powershell").Columns.Single(c => c.Tactic == MitreTactic.Execution);
        Assert.False(exec.Hidden);
        Assert.Contains(exec.Rows, r => r.Row.Parent.Id == "T1059" && r.ShownSubs.Any(s => s.Id == "T1059.001"));

        Assert.True(AttackMatrixView.For("qqzzxv").NoMatches);
    }
}
