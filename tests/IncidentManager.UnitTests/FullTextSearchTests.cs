using System.Linq.Expressions;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Search;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// CAP-22: the full-text search condition built from what a user typed, the rewrite of a query's text matches into
/// full-text or substring SQL, and how the server's report of its indexes reads as a search mode.
/// </summary>
public sealed class FullTextSearchTests
{
    // --- The search condition ---

    [Theory]
    [InlineData("lsass", "\"lsass*\"")]
    [InlineData("LSA", "\"LSA*\"")]
    [InlineData("  padded  ", "\"padded*\"")]
    [InlineData("2026", "\"2026*\"")]
    [InlineData("ws-001234", "\"ws-001234*\"")]
    [InlineData("o'brien", "\"o'brien*\"")]
    [InlineData("it's", "\"it's*\"")]
    [InlineData("c++", "\"c++*\"")]
    [InlineData("evil.example.com", "\"evil.example.com*\"")]
    public void A_word_becomes_one_quoted_prefix_term(string typed, string condition) =>
        FullTextCondition.For(typed).Should().Be(condition);

    [Theory]
    [InlineData("lateral movement", "\"lateral movement*\"")]
    [InlineData("lateral   movement", "\"lateral movement*\"")]
    [InlineData("lateral\tmovement\r\nnow", "\"lateral movement now*\"")]
    public void A_phrase_stays_one_phrase_with_its_spacing_tidied(string typed, string condition) =>
        FullTextCondition.For(typed).Should().Be(condition);

    [Theory]
    [InlineData("AND", "\"AND*\"")]
    [InlineData("or", "\"or*\"")]
    [InlineData("NEAR", "\"NEAR*\"")]
    [InlineData("NOT", "\"NOT*\"")]
    [InlineData("a AND b", "\"a AND b*\"")]
    [InlineData("x OR 1=1", "\"x OR 1=1*\"")]
    [InlineData("NEAR((a,b),5)", "\"NEAR((a,b),5)*\"")]
    [InlineData("FORMSOF(INFLECTIONAL, run)", "\"FORMSOF(INFLECTIONAL, run)*\"")]
    [InlineData("ISABOUT(a WEIGHT(.9))", "\"ISABOUT(a WEIGHT(.9))*\"")]
    [InlineData("a~b", "\"a~b*\"")]
    [InlineData("a & b | !c", "\"a & b | !c*\"")]
    [InlineData("'; DROP TABLE Cases; --", "\"'; DROP TABLE Cases; --*\"")]
    public void Operators_a_user_types_are_words_inside_the_quotes(string typed, string condition) =>
        FullTextCondition.For(typed).Should().Be(condition);

    [Theory]
    [InlineData("say \"hi\"", "\"say hi*\"")]
    [InlineData("\"quoted\"", "\"quoted*\"")]
    [InlineData("ab\"\"cd", "\"ab cd*\"")]
    [InlineData("pass*", "\"pass*\"")]
    [InlineData("*pass", "\"pass*\"")]
    [InlineData("pa*ss", "\"pa ss*\"")]
    [InlineData("pass**", "\"pass*\"")]
    public void Quotes_and_stars_can_never_end_the_term_or_add_a_wildcard(string typed, string condition) =>
        FullTextCondition.For(typed).Should().Be(condition);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\r\n")]
    [InlineData("*")]
    [InlineData("\"")]
    [InlineData("\"*\"")]
    [InlineData("~")]
    [InlineData("&|!")]
    [InlineData("--")]
    [InlineData("()")]
    [InlineData("...")]
    [InlineData("\u200B")]          // a zero-width space: a format character
    [InlineData("\u0000\u0007")]    // control characters
    [InlineData("\U0001F525")]      // an emoji alone: a symbol, not a word
    public void Nothing_with_no_letter_or_digit_is_a_condition(string? typed) =>
        FullTextCondition.For(typed).Should().BeNull("it's matched as a substring instead");

    [Theory]
    [InlineData("caf\u00E9", "\"caf\u00E9*\"")]
    [InlineData("\u00C4RGER", "\"\u00C4RGER*\"")]
    [InlineData("\u043F\u0430\u0440\u043E\u043B\u044C", "\"\u043F\u0430\u0440\u043E\u043B\u044C*\"")]
    [InlineData("\u5BC6\u7801", "\"\u5BC6\u7801*\"")]
    [InlineData("\u0643\u0644\u0645\u0629", "\"\u0643\u0644\u0645\u0629*\"")]
    [InlineData("e\u0301t\u00E9", "\"e\u0301t\u00E9*\"")]   // a combining accent stays with its letter
    [InlineData("\U0001F525fire", "\"\U0001F525fire*\"")]
    [InlineData("\U0001D400bold", "\"\U0001D400bold*\"")]  // a letter outside the BMP (a surrogate pair)
    [InlineData("zero\u200Bwidth", "\"zero width*\"")]
    [InlineData("bell\u0007char", "\"bell char*\"")]
    [InlineData("lone\uD800surrogate", "\"lone surrogate*\"")]
    public void Unicode_letters_count_and_invisible_or_broken_characters_break_words(string typed, string condition) =>
        FullTextCondition.For(typed).Should().Be(condition);

    [Fact]
    public void A_term_too_long_for_a_word_is_matched_as_a_substring()
    {
        FullTextCondition.For(new string('a', FullTextCondition.MaxLength)).Should().Be("\"" + new string('a', FullTextCondition.MaxLength) + "*\"");
        FullTextCondition.For(new string('a', FullTextCondition.MaxLength + 1)).Should().BeNull();
    }

    [Fact]
    public void Whatever_is_typed_the_condition_is_one_prefix_term_in_one_pair_of_quotes()
    {
        string[] nasty =
        [
            "\"a\" OR \"b\"", "\"\"\"", "a\"*\"b", "*\"*", "NEAR(\"a\",\"b\")", "x\" OR \"y*", "\\\"escape", "%_[]^", "100%",
            "{0} {1}", "N'x'", "a\u2028b", "a\uFEFFb", "\uFFFD", "\uFB01 ligature", "\u0130stanbul", "\u00DF",
        ];
        foreach (var typed in nasty)
        {
            var c = FullTextCondition.For(typed);
            if (c is null) continue;
            c.Should().StartWith("\"").And.EndWith("*\"");
            c.Count(ch => ch == '"').Should().Be(2, typed);
            c.Count(ch => ch == '*').Should().Be(1, typed);
            c[1..^2].Should().NotStartWith(" ").And.NotEndWith(" ");
        }
    }

    // --- The rewrite ---

    // A stand-in for the provider's CONTAINS: true when the column equals the condition, so the test can see which ran.
    private sealed class FakeFullText(params (Type, string)[] covered) : IFullTextSearch
    {
        public FullTextStatus Status { get; } = new(FullTextMode.Partial, covered.ToHashSet(), DateTimeOffset.UnixEpoch);
        public Task<FullTextStatus> StatusAsync(CancellationToken ct = default) => Task.FromResult(Status);
        public Task<FullTextStatus> RefreshAsync(CancellationToken ct = default) => Task.FromResult(Status);
        public Expression<Func<string?, string, bool>> ContainsTemplate { get; } = (column, condition) => column == condition;
        public bool IsFullTextFailure(Exception ex) => false;
        public void FellBack(Exception ex, string search) { }
        public Task<FullTextStatus> CreateIndexesAsync(CancellationToken ct = default) => Task.FromResult(Status);
    }

    private static FullTextPlan Plan(params (Type, string)[] covered)
    {
        var ft = new FakeFullText(covered);
        return new FullTextPlan(ft, ft.Status);
    }

    [Fact]
    public void Without_a_plan_every_column_is_a_case_insensitive_substring_match()
    {
        const string t = "lsa";
        string? c = null;
        var match = TextMatch.Prepare<TimelineEntry>(e => TextMatch.Has(e.Description, t, c) || TextMatch.Has(e.Rationale, t, c), null).Compile();

        match(new TimelineEntry { Description = "Dumped LSASS memory" }).Should().BeTrue();
        match(new TimelineEntry { Description = "nothing", Rationale = "salsa" }).Should().BeTrue("a substring, anywhere");
        match(new TimelineEntry { Description = "nothing", Rationale = null }).Should().BeFalse("a null column doesn't match");
        TextMatch.Prepare<TimelineEntry>(e => TextMatch.Has(e.Description, t, c), null).ToString().Should().NotContain(nameof(TextMatch.Has));
    }

    [Fact]
    public void With_a_plan_only_the_covered_columns_use_the_full_text_predicate()
    {
        const string t = "lsa";
        var cond = FullTextCondition.For(t);
        var match = TextMatch.Prepare<TimelineEntry>(e => TextMatch.Has(e.Description, t, cond) || TextMatch.Has(e.Rationale, t, cond),
            Plan((typeof(TimelineEntry), nameof(TimelineEntry.Description)))).Compile();

        match(new TimelineEntry { Description = "\"lsa*\"" }).Should().BeTrue("the description went through the provider's predicate");
        match(new TimelineEntry { Description = "Dumped LSASS memory" }).Should().BeFalse("so a substring of it no longer counts");
        match(new TimelineEntry { Description = "x", Rationale = "salsa" }).Should().BeTrue("the rationale isn't covered: still a substring");
    }

    private static Case NewCase(string title) =>
        Case.Open(2026, 1, "X", title, IncidentManager.Domain.Enums.Classification.Incident, IncidentManager.Domain.Enums.Severity.Low,
            IncidentManager.Domain.Enums.CaseOrigin.InternalDetection, "u", DateTimeOffset.UnixEpoch);

    [Fact]
    public void Columns_inside_a_nested_lambda_and_another_entity_are_rewritten_too()
    {
        const string t = "phish";
        var cond = FullTextCondition.For(t);
        var plan = Plan((typeof(CaseBrief), nameof(CaseBrief.WorkingAssessment)));
        var match = TextMatch.Prepare<Case>(c => TextMatch.Has(c.Title, t, cond)
                                                 || c.Briefs.Any(b => b.IsCurrent && TextMatch.Has(b.WorkingAssessment, t, cond)), plan).Compile();

        var hit = NewCase("x");
        hit.Briefs.Add(new CaseBrief { IsCurrent = true, WorkingAssessment = "\"phish*\"" });
        match(hit).Should().BeTrue();
        match(NewCase("Phishing wave")).Should().BeTrue("the case title isn't covered: a substring");
        var old = NewCase("x");
        old.Briefs.Add(new CaseBrief { IsCurrent = false, WorkingAssessment = "\"phish*\"" });
        match(old).Should().BeFalse("the rest of the predicate is kept");
    }

    [Fact]
    public void The_same_property_name_on_another_entity_is_not_covered()
    {
        const string t = "x";
        var cond = FullTextCondition.For(t);
        var match = TextMatch.Prepare<ActionItem>(a => TextMatch.Has(a.Description, t, cond),
            Plan((typeof(TimelineEntry), nameof(TimelineEntry.Description)))).Compile();
        match(new ActionItem { Title = "t", Description = "box" }).Should().BeTrue("a task's description is matched by substring here");
    }

    [Fact]
    public void Called_directly_the_marker_is_the_substring_match()
    {
        TextMatch.Has("Dumped LSASS", "lsa", "\"lsa*\"").Should().BeTrue();
        TextMatch.Has(null, "lsa", null).Should().BeFalse();
    }

    // --- The status ---

    private static readonly DateTimeOffset At = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private static IEnumerable<(string, string, bool, int)> All(int populate = 0) =>
        FullTextSchema.Columns.Select(c => (c.Table.Name, c.Column, true, populate));

    [Fact]
    public void Every_column_indexed_and_idle_is_ready()
    {
        var s = SqlFullTextSearch.Classify(All(), At);
        s.Mode.Should().Be(FullTextMode.Ready);
        s.Label.Should().Be("Search: full-text (SQL Server)");
        s.Covers(typeof(TimelineEntry), nameof(TimelineEntry.Description)).Should().BeTrue();
        s.Covers(typeof(AnalystNote), nameof(AnalystNote.Body)).Should().BeTrue();
        s.Covers(typeof(CaseEntity), nameof(CaseEntity.Value)).Should().BeFalse("indicators stay exact");
        SqlFullTextSearch.Classify(All(populate: 9), At).Mode.Should().Be(FullTextMode.Ready, "change tracking at work is searchable");
    }

    [Fact]
    public void Nothing_indexed_is_not_created_and_still_filling_is_populating()
    {
        SqlFullTextSearch.Classify([], At).Mode.Should().Be(FullTextMode.NotCreated);
        SqlFullTextSearch.Classify([("SomeOtherTable", "Body", true, 0)], At).Mode.Should().Be(FullTextMode.NotCreated);
        var filling = SqlFullTextSearch.Classify(All(populate: 1), At);
        filling.Mode.Should().Be(FullTextMode.Populating);
        filling.Any.Should().BeFalse("nothing is searched by word until it's filled");
        filling.Label.Should().Contain("substring");
    }

    [Fact]
    public void Some_columns_ready_is_partial_and_names_the_rest()
    {
        var rows = All().Where(r => r.Item1 != "AnalystNotes").Append(("AnalystNotes", "Body", false, 0));
        var s = SqlFullTextSearch.Classify(rows, At);
        s.Mode.Should().Be(FullTextMode.Partial);
        s.Covers(typeof(AnalystNote), nameof(AnalystNote.Body)).Should().BeFalse("a disabled index isn't used");
        s.Covers(typeof(TimelineEntry), nameof(TimelineEntry.Description)).Should().BeTrue();
        s.Detail.Should().Contain("AnalystNotes.Body");
    }

    [Fact]
    public void A_filling_index_with_a_column_never_indexed_names_it_and_offers_to_create_it()
    {
        // CAP-22 review: one column with no index at all while the rest fill read only as Populating, which hid Create.
        var s = SqlFullTextSearch.Classify(All(populate: 1).Where(r => r.Item1 != "AnalystNotes"), At);
        s.Mode.Should().Be(FullTextMode.Populating);
        s.NotIndexed.Should().Equal("AnalystNotes.Body");
        s.Detail.Should().Contain("not indexed: AnalystNotes.Body");
        s.CanCreate.Should().BeTrue();

        SqlFullTextSearch.Classify(All(populate: 1), At).CanCreate.Should().BeFalse("everything is indexed, only filling");
        SqlFullTextSearch.Classify(All(), At).CanCreate.Should().BeFalse();
        SqlFullTextSearch.Classify([], At).CanCreate.Should().BeTrue();
        SqlFullTextSearch.Classify([], At).NotIndexed.Should().HaveCount(FullTextSchema.Columns.Count());
    }

    [Fact]
    public void Evidence_file_names_are_not_indexed_so_part_of_one_still_finds_it()
    {
        // CAP-22 review (F2): the word breaker keeps lsass_dump.dmp as one token, so by word "dump" missed it.
        FullTextSchema.Columns.Should().NotContain(c => c.Table.Name == "Evidence" && c.Column == nameof(Evidence.OriginalFileName));
        FullTextSchema.Columns.Should().Contain(c => c.Table.Name == "Evidence" && c.Column == nameof(Evidence.Description));
        FullTextSchema.Script.Should().NotContain("OriginalFileName");
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("Auto", false)]
    [InlineData("auto", false)]
    [InlineData("Substring", true)]
    [InlineData(" substring ", true)]
    [InlineData("1", false)]           // BUG-592: by name only, never a number
    [InlineData("Off", false)]         // not a mode: the default
    public void Search_mode_is_read_by_name_and_only_Substring_turns_word_search_off(string? value, bool off)
    {
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [SqlFullTextSearch.ModeKey] = value }).Build();
        new SqlFullTextSearch(null!, new FullTextStatusCache(), null!, config: config).TurnedOff.Should().Be(off);
    }

    [Fact]
    public void Turned_off_nothing_is_searched_by_word_and_the_indexes_state_is_kept_for_diagnostics()
    {
        var s = SqlFullTextSearch.Classify(All(), At).Off();
        s.Any.Should().BeFalse();
        s.TurnedOff.Should().BeTrue();
        s.Mode.Should().Be(FullTextMode.Ready, "the indexes are still there and filled");
        s.Label.Should().Be("Search: substring (full-text turned off by the Search mode setting)");
        s.Detail.Should().Be("The indexes: full-text (SQL Server).");
        s.CanCreate.Should().BeFalse();
        s.Off().Should().BeSameAs(s);
        SqlFullTextSearch.Classify([], At).Off().CanCreate.Should().BeTrue("Create is still offered while it's off");
    }

    [Fact]
    public void Each_mode_has_its_diagnostics_line()
    {
        FullTextStatus.Substring(FullTextMode.NotInstalled, At).Label.Should().Be("Search: substring (full-text not installed)");
        FullTextStatus.Substring(FullTextMode.NotSqlServer, At).Label.Should().Be("Search: substring (SQLite)");
        foreach (var mode in Enum.GetValues<FullTextMode>())
            FullTextStatus.Substring(mode, At).Label.Should().StartWith("Search: ");
    }

    [Theory]
    [InlineData(7601, true)]   // not full-text indexed
    [InlineData(7609, true)]   // Full-Text Search not installed
    [InlineData(7630, true)]   // syntax error in the search condition
    [InlineData(7645, true)]   // empty full-text predicate
    [InlineData(9928, true)]
    [InlineData(30053, true)]  // word breaking timed out
    [InlineData(208, false)]   // invalid object name
    [InlineData(1205, false)]  // deadlock
    [InlineData(-2, false)]    // timeout
    public void Only_full_text_errors_fall_back(int number, bool fallsBack) =>
        SqlFullTextSearch.IsFullTextErrorNumber(number).Should().Be(fallsBack);

    [Fact]
    public void The_schema_names_each_column_once_and_the_script_creates_only_what_is_missing()
    {
        FullTextSchema.Columns.Select(c => (c.Table.Name, c.Column)).Should().OnlyHaveUniqueItems();
        FullTextSchema.Tables.Select(t => t.Entity).Should().OnlyHaveUniqueItems();
        var script = FullTextSchema.Script;
        script.Should().StartWith("-- CAP-22").And.Contain("SERVERPROPERTY('IsFullTextInstalled')");
        script.Should().NotContain("BEGIN TRAN", "full-text DDL can't run in a transaction");
        foreach (var t in FullTextSchema.Tables)
        {
            script.Should().Contain($"KEY INDEX [{t.KeyIndex}] ON [{FullTextSchema.Catalog}] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)");
            foreach (var c in t.Columns) script.Should().Contain($"ADD ([{c}] LANGUAGE 1033)");
        }
        FullTextSchema.DropScript.Should().Contain($"DROP FULLTEXT CATALOG [{FullTextSchema.Catalog}]");
    }
}
