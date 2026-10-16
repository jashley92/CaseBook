using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// C3 (BUG-436, 477, 503, 521, 553, 571, 582): a stored instant shown in a wall-clock field is re-derived from the field
/// only when the user changed it (to the minute shown); left alone, the stored instant is sent back. Converting it back
/// reads a time in the repeated autumn hour as standard time, so editing anything else moved it an hour. The one rule
/// lives in WallClock.Kept (a date and time), DayValues.Kept (a due) and TransitionDraft.KeptAt (a dialog's time).
/// These scans fail when a component keeps its own wall/UTC conversion, converts a field seeded from a stored instant
/// back without the kept rule, or sets a draft's time to a stored instant other than through KeptAt.
/// </summary>
/// <remarks>What it can't see: a seeded value passed to another method before it's converted (the conversion is then
/// in code that doesn't know where the value came from; a local or a tuple in the seeding method is followed, BUG-615);
/// a stored instant carried in a property
/// of another object than a TransitionDraft. KeptTimeTests (integration) checks the helpers' behaviour.</remarks>
public partial class WallClockRoundTripTests
{
    // Wave 2b: private wall/UTC copies and the old kept helpers, still in the tab components (2b moves each to
    // WallClock / DayValues and takes its entry off).
    private static readonly Dictionary<string, int> Copies = new(StringComparer.Ordinal)
    {
    };

    // Wave 2b: fields seeded from a stored instant and also converted straight back somewhere.
    private static readonly Dictionary<string, int> Rederived = new(StringComparer.Ordinal)
    {

    };

    private static readonly string[] HelperFiles = ["Pages/Workspace/TransitionDraft.cs", "Pages/Workspace/DayValues.cs"];

    [Fact]
    public void No_component_keeps_its_own_wall_clock_conversion()
    {
        var found = new List<(string File, string What)>();
        foreach (var s in Sources().Where(s => !HelperFiles.Contains(s.File)))
        {
            foreach (Match m in Copy().Matches(s.Code))
                found.Add((s.File, $"{m.Groups["name"].Value} (line {s.LineOf(m.Index)})"));
        }
        var (offenders, stale) = Against(Copies, found);
        offenders.Should().BeEmpty("wall times go to and from UTC through WallClock (and DayValues for a due), one rule for all");
        stale.Should().BeEmpty("a removed copy comes off the wave-2b list");
    }

    [Fact]
    public void A_field_seeded_from_a_stored_instant_goes_back_through_the_kept_rule()
    {
        var (offenders, stale) = Against(Rederived, Components().SelectMany(c => RederivedIn(c.File, c.Parts)));
        offenders.Should().BeEmpty("a field filled from a stored instant is saved with WallClock.Kept / DayValues.Kept");
        stale.Should().BeEmpty("a fixed site comes off the wave-2b list");
    }

    [Fact]
    public void A_draft_is_given_a_stored_instant_through_KeptAt()
    {
        // BUG-582: Transition.When = ToWall(offer.At) re-read the offered instant from the wall on Apply.
        var found = Sources()
            .SelectMany(s => DraftWhen().Matches(s.Code).Where(m => !IsNow(m.Groups["arg"].Value))
                .Select(m => $"{s.File}:{s.LineOf(m.Index)} {m.Value.Trim()}"))
            .ToList();
        found.Should().BeEmpty("TransitionDraft.KeptAt keeps the instant while its minute is left as shown");
    }

    [Theory]
    [InlineData("private void A(X offer) { _action.Transition.When = WallClock.ToWall(offer.At, TimeDisp.Zone); _action.Transition.Edited = true; }", true)]
    [InlineData("private void A() { a.Transition.Reset(WallClock.ToWall(Clock.UtcNow, TimeDisp.Zone)); a.Transition.When = WallClock.ToWall(Clock.UtcNow, z); }", false)]
    public void The_draft_scan_tells_a_stored_instant_from_now(string snippet, bool flagged) =>
        DraftWhen().Matches(Strip(snippet)).Any(m => !IsNow(m.Groups["arg"].Value)).Should().Be(flagged);

    [Fact]
    public void The_rederive_scan_sees_a_seeded_field_converted_back()
    {
        var parts = new[] { new Source("Pages/X.razor", Strip(
            "private void Begin(E e) { _when = UtcToWall(e.OccurredAtUtc); } private async Task Save() { await Cases.EditAsync(Id, WallToUtc(_when)); }"), "") };
        RederivedIn("Pages/X.razor", parts).Should().ContainSingle();
        var kept = new[] { new Source("Pages/X.razor", Strip(
            "private void Begin(E e) { _when = UtcToWall(e.OccurredAtUtc); } private async Task Save() { await Cases.EditAsync(Id, WallClock.Kept(_when, _shown, _rec, z)); }"), "") };
        RederivedIn("Pages/X.razor", kept).Should().BeEmpty();
    }

    [Theory]   // BUG-615: a seed carried through a local, a tuple or a conditional
    [InlineData("private void Begin(T t) { if (t.Due is { } due) { var shown = DayValues.FromUtc(due, z, o); (_date, _time) = shown; } } private Task Save() => Cases.SaveAsync(ToDueUtc(_date, _time));", true)]
    [InlineData("private void Begin(T t) { var (d, tm) = DayValues.FromUtc(t.Due, z, o); _date = d; } private Task Save() => Cases.SaveAsync(ToDueUtc(_date, null));", true)]
    [InlineData("private void Begin(E e) { _when = e.At is { } a ? WallClock.ToWall(a, z) : null; } private Task Save() => Cases.SaveAsync(ToUtc(_when));", true)]
    [InlineData("private void Begin() { var shown = DayValues.FromUtc(Clock.UtcNow, z, o); (_date, _time) = shown; } private Task Save() => Cases.SaveAsync(ToDueUtc(_date, _time));", false)]
    [InlineData("private void Begin(T t) { var shown = DayValues.FromUtc(t.Due, z, o); (_date, _time) = shown; } private Task Save() => Cases.SaveAsync(DayValues.Kept(_date, _time, _shown, _stored, z, o));", false)]
    public void The_rederive_scan_follows_a_seed_through_locals(string snippet, bool flagged)
    {
        var parts = new[] { new Source("Pages/X.razor", Strip(snippet), "") };
        RederivedIn("Pages/X.razor", parts).Any().Should().Be(flagged);
    }

    private static IEnumerable<(string File, string What)> RederivedIn(string file, IReadOnlyList<Source> parts)
    {
        var code = string.Concat(parts.Select(p => p.Code));
        var seeded = Seed().Matches(code).Where(m => !IsNow(m.Groups["arg"].Value)).Select(m => m.Groups["field"].Value)
            .ToHashSet(StringComparer.Ordinal);
        foreach (var m in parts.SelectMany(p => Methods(p.Code))) SeededThrough(m.Body, seeded);
        foreach (var m in parts.SelectMany(p => Methods(p.Code)))
        {
            if (KeptCall().IsMatch(m.Body)) continue;   // the method decides with the kept rule
            foreach (Match back in Back().Matches(m.Body))
                if (seeded.Contains(back.Groups["field"].Value))
                    yield return (file, $"{m.Name}: {back.Value.Trim()}");
        }
    }

    /// <summary>
    /// BUG-615: the fields a method seeds from a stored instant through a local or a tuple
    /// (<c>var shown = DayValues.FromUtc(due, ...); (_date, _time) = shown;</c>), or in a conditional
    /// (<c>_x = at is { } d ? WallClock.ToWall(d, z) : null</c>). Locals are the method's own; fields are added to
    /// <paramref name="seeded"/>.
    /// </summary>
    private static void SeededThrough(string body, HashSet<string> seeded)
    {
        var locals = new HashSet<string>(StringComparer.Ordinal);
        for (var pass = 0; pass < 2; pass++)   // a copy written above the line that seeds its source is seen on the second pass
        {
            foreach (var statement in body.Split(';'))
            {
                if (Assignment().Match(statement) is not { Success: true } a) continue;
                var rhs = a.Groups["rhs"].Value;
                var fromStored = Conversion().Matches(rhs).Any(c => !IsNow(c.Groups["arg"].Value))
                    || (BareName().Match(rhs.Trim()) is { Success: true } n && (locals.Contains(n.Value) || seeded.Contains(n.Value)));
                if (!fromStored) continue;
                var targets = Names().Matches(a.Groups["lhs"].Value).Select(t => t.Value)
                    .Concat(ChainedTarget().Matches(rhs).Select(t => t.Groups["name"].Value));
                foreach (var t in targets.Where(t => t != "var"))
                    (t.StartsWith('_') ? seeded : locals).Add(t);
            }
        }
    }

    // A conversion's argument that is the current time (a fresh default), not a stored instant.
    private static bool IsNow(string arg) => NowArg().IsMatch(arg.Trim());

    // A method of a component's own that turns a wall time into UTC or back (or keeps one), by the names they've had.
    [GeneratedRegex(@"(?:private|protected|public|internal)\s+(?:static\s+)?[\w.?<>]+\s+(?<name>WallToUtc|UtcToWall|ToWall|KeptOrTyped\w*)\s*\(",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Copy();

    [GeneratedRegex(@"(?<field>_\w+)\s*=\s*(?:_\w+\s*=\s*)?(?:[\w.]*\.)?(?:UtcToWall|ToWall|FromUtc)\(\s*(?<arg>[^,)]+)", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Seed();

    // The first assignment in a statement: `var x =`, `_x =`, `(_a, _b) =`, `var (a, b) =` (not `==`, `=>`, `x.Y =`).
    [GeneratedRegex(@"(?<![.\w])(?<lhs>(?:var\s+)?(?:\(\s*(?:var\s+)?[_a-z]\w*(?:\s*,\s*(?:var\s+)?[_a-z]\w*)+\s*\)|[_a-z]\w*))\s*=(?![=>])(?<rhs>[^;]*)$",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Assignment();

    [GeneratedRegex(@"\b(?:UtcToWall|ToWall|FromUtc)\(\s*(?<arg>[^,)]+)", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Conversion();

    [GeneratedRegex(@"^[_a-z]\w*$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex BareName();

    [GeneratedRegex(@"[_a-z]\w*", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Names();

    [GeneratedRegex(@"(?<![.\w])(?<name>_\w+)\s*=(?![=>])", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex ChainedTarget();

    [GeneratedRegex(@"\.When\s*=\s*(?:[\w.]*\.)?(?:UtcToWall|ToWall)\(\s*(?<arg>[^,)]+)", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex DraftWhen();

    [GeneratedRegex(@"(?:WallToUtc|\bToUtc|ToDueUtc)\(\s*(?<field>_\w+)\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Back();

    [GeneratedRegex(@"\b(?:Kept|KeptAt|KeptOrTyped\w*|KeptWhenUtc|CorrectedUtc|DecidedOnUtc)\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex KeptCall();

    [GeneratedRegex(@"^(?:Clock\.UtcNow|DateTimeOffset\.UtcNow|DateTime\.UtcNow|now|nowUtc|Now)$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex NowArg();
}
