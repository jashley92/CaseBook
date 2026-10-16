using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-601 (C5): late async continuations. Code after an await runs in a world that may have moved on: another case or
/// row is open, a newer load started, the text was edited, the page was left. Each scan reads the component sources
/// (ComponentSourceScanner) for one shape of the class:
/// A. a method that checks its result is for what's open (IsFor, a sequence, the case id) checks again after every
///    later await before changing state (BUG-337, BUG-601's supersede follow-up);
/// B. a load that replaces shown state is sequenced (LoadSequence, KeyedLoad, or its own counter);
/// C. text cleared after a save is cleared only if it still holds what was sent (DraftText.ClearIfUnchanged);
/// D. a row's form closed after a save is closed only if it's still that form (FormSession.CloseIf);
/// E. a navigation after an await first checks the page is still shown.
/// </summary>
/// <remarks>What it can't see: a guard by a name it doesn't know; state changed through a method call rather than an
/// assignment (A, B); a field cleared through a local alias (C, D); a stale result kept in a local and acted on later.
/// The lifetime rule (nothing registered after an await without a disposed check) is ComponentLifetimeTests.</remarks>
public partial class ComponentContinuationTests
{
    // Wave 2b allow-lists, by file: the count of sites still to fix, with what they are.
    private static readonly Dictionary<string, int> A_NotRechecked = new(StringComparer.Ordinal)
    {
        // wave 2b, U4 (pages, admin, other shared)
        ["Shared/ReportTemplateLibrary.razor"] = 1,   // OpenPreview: _cases = page.Items.ToList();
    };

    private static readonly Dictionary<string, int> B_Unsequenced = new(StringComparer.Ordinal)
    {
        // wave 2b, U1 (timeline, notes)
        ["Pages/CaseTabs/CaseNotesTab.razor"] = 1,   // OnParametersSetAsync: _mentionable = await Cases.MentionableAsync
        ["Pages/CaseTabs/CaseTimelineTab.razor"] = 2,   // ReconcileEditor: _mentionable = await Cases.MentionableAsync; SearchFuLink: _fuLinkResults = found (Cases.SearchLinkableCasesAsync)
        // wave 2b, U3 (entities, overview, panels, evidence)
        ["Pages/CaseTabs/CaseEntitiesTab.razor"] = 3,   // OnParametersSetAsync: _links = await Cases.GetCaseLinksAsync; LoadOverlaps: _overlaps = await Cases.FindEntityOverlapsAsync; LoadRelated: _related...
        ["Pages/CaseTabs/CaseOverviewTab.razor"] = 5,   // SaveNotice: _deadlines = await Deadlines.EvaluateAsync; MarkReported: _deadlines = await Deadlines.EvaluateAsync; OnParametersSetAsync: _lessons =...
        // wave 2b, U4 (pages, admin, other shared)
        ["Pages/Admin.razor"] = 3,   // LoadAsync: _effective = await Settings.GetEffectiveAsync; LoadAsync: _ledger = await Ledger.GetAsync; LoadAsync: _logoDataUri = logo (Branding.GetLogoAsync)
        ["Pages/AdminApiTokens.razor"] = 2,   // LoadAsync: _roles = await Roles.ListRolesAsync; LoadAsync: _tokens = await Tokens.ListAllAsync
        ["Pages/AdminDataElements.razor"] = 1,   // LoadAsync: _active = all (DataElements.ListAllAsync)
        ["Pages/AdminEmailTemplates.razor"] = 2,   // Save: _views = await Templates.GetAllAsync; Reset: _views = await Templates.GetAllAsync
        ["Pages/AdminOutcomes.razor"] = 1,   // LoadAsync: _active = all (Outcomes.ListAllAsync)
        ["Pages/AdminRoles.razor"] = 3,   // LoadAsync: _roles = await Roles.ListRolesAsync; LoadAsync: _mappings = await Roles.ListMappingsAsync; LoadAsync: _review = await AccessReview.BuildAsync
        ["Pages/AgendaPage.razor"] = 1,   // Load: _board = board (Svc.GetBoardAsync)
        ["Pages/CampaignPage.razor"] = 1,   // OnParametersSetAsync: _rollup = await Svc.GetRollupAsync
        ["Pages/CaseImport.razor"] = 5,   // ReopenStuck: _pending = await Import.ListPendingAsync; OnParametersSetAsync: _pending = await Import.ListPendingAsync; OnParametersSetAsync: _preview = preview ...
        ["Pages/CaseTabs/CaseReportTab.razor"] = 1,   // LoadReports: _reports = await Reports.ListAsync
        ["Pages/CaseTabs/CaseReviewTab.razor"] = 4,   // Load: _view = await Lessons.GetForCaseAsync; Load: _reports = await Reports.ListAsync; OnGenerated: _reports = await Reports.ListAsync; ApproveRepor...
        ["Pages/CreateCase.razor"] = 1,   // CheckOverlapsCore: _outcomeLabels = await Outcomes.LabelsAsync
        ["Pages/FindPage.razor"] = 1,   // Run: _result = result (Finder.FindAsync)
        ["Pages/ImprovementActionsPage.razor"] = 1,   // Load: _register = register (Lessons.GetRegisterAsync)
        ["Pages/IndicatorsPage.razor"] = 1,   // Load: _library = library (Indicators.SearchAsync)
        ["Pages/ProgramReportPage.razor"] = 1,   // Load: _report = report (Program.BuildAsync)
        ["Shared/CasePeek.razor"] = 1,   // OnParametersSetAsync: _p = p (Cases.GetPreviewAsync)
        ["Shared/ReportProfilesEditor.razor"] = 2,   // LoadAsync: _profiles = await Profiles.ListAllAsync; LoadAsync: _templates = await Templates.ListActiveAsync
        ["Shared/ReportTemplateLibrary.razor"] = 1,   // OpenPreview: _cases = page (Cases.ListAsync)
        ["Shared/TeamWorkloadPanel.razor"] = 1,   // LoadWorkload: _w = await Workload.GetAsync
        ["Shared/UndeliveredAlertBanner.razor"] = 2,   // LoadAsync: _alerts = await Alerts.ListAsync; Dismiss: _alerts = await Alerts.ListAsync
    };

    private static readonly Dictionary<string, int> C_ClearedOverTyping = new(StringComparer.Ordinal)
    {
        // wave 2b, U1 (timeline, notes)
        ["Pages/CaseTabs/CaseTimelineTab.razor"] = 7,   // AddQuestion: _question = null;; AddTimelineCore: _tlDesc = "";; AddTimelineCore: _tlSource = null;; AddEventStepCore: _tlDesc = "";; AddEventStepC...
        // wave 2b, U3 (entities, overview, panels, evidence)
        ["Pages/CaseTabs/CaseEntitiesTab.razor"] = 6,   // AddEntity: _enValue = "";; AddEntity: _enLabel = null;; AddEntity: _enDescription = null;; AddEntity: _enSource = null;; AddRelationship: _relSour...
        ["Pages/CaseTabs/CaseOverviewTab.razor"] = 1,   // AddLink: _linkDesc = null;
        // wave 2b, U4 (pages, admin, other shared)
        ["Pages/AccountApiTokens.razor"] = 1,   // CreateToken: _name = "";
        ["Pages/AdminRoles.razor"] = 1,   // AddMappingCore: _newGroup = "";
        ["Pages/CaseImport.razor"] = 1,   // Reject: _rejectNote = null;
        ["Shared/ReportTemplateLibrary.razor"] = 1,   // Upload: _newName = null;
    };

    private static readonly Dictionary<string, int> D_ClosesAnotherForm = new(StringComparer.Ordinal)
    {
        // wave 2b, U3 (entities, overview, panels, evidence)
        ["Pages/CaseTabs/CaseEntitiesTab.razor"] = 2,   // SaveRelationship: _relEditId = null;; SaveRelationship: _relEditId = null;
        // wave 2b, U4 (pages, admin, other shared)
        ["Pages/CaseImport.razor"] = 2,   // OnParametersSetAsync: _reviewingPendingId = null;; Reject: _reviewingPendingId = null;
        ["Pages/CaseTabs/CaseReviewTab.razor"] = 2,   // SaveEdit: _editingId = null;; SaveEdit: _editingId = null;
    };

    private static readonly Dictionary<string, int> E_NavigatesLate = new(StringComparer.Ordinal)
    {
        // wave 2b, U4 (pages, admin, other shared)
        ["Pages/Admin.razor"] = 1,   // OnBeforeLeave<lambda>: Nav.NavigateTo(
        ["Pages/CaseByNumber.razor"] = 1,   // OnParametersSetAsync: Nav.NavigateTo(
        ["Pages/CaseImport.razor"] = 4,   // ReopenStuck: Nav.NavigateTo(; OnParametersSetAsync: Nav.NavigateTo(; Reject: Nav.NavigateTo(; Apply: Nav.NavigateTo(
        ["Pages/CreateCase.razor"] = 1,   // SubmitCore: Nav.NavigateTo(
        ["Pages/Home.razor"] = 1,   // OnInitializedAsync: Nav.NavigateTo(
        ["Shared/CaseTabStrip.razor"] = 1,   // Close: Nav.NavigateTo(
        ["Shared/ErrorFallback.razor"] = 1,   // Retry: Nav.NavigateTo(
    };

    [Fact]
    public void A_A_result_checked_for_what_is_open_is_checked_again_after_each_await() =>
        Check(A_NotRechecked, Scan(NotRechecked), "a continuation acts only while its case or row is still the one open");

    [Fact]
    public void B_A_load_that_replaces_what_is_shown_is_sequenced() =>
        Check(B_Unsequenced, Scan(Unsequenced), "an older load landing last shows the wrong thing (LoadSequence / KeyedLoad)");

    [Fact]
    public void C_Text_is_cleared_after_a_save_only_if_unchanged() =>
        Check(C_ClearedOverTyping, Scan(ClearedOverTyping), "what was typed during the save is kept (DraftText.ClearIfUnchanged)");

    [Fact]
    public void D_A_save_closes_only_its_own_form() =>
        Check(D_ClosesAnotherForm, Scan(ClosesAnotherForm), "another row's form, opened during the save, stays open (FormSession.CloseIf)");

    [Fact]
    public void E_A_navigation_after_an_await_checks_the_page_is_still_shown() =>
        Check(E_NavigatesLate, Scan(NavigatesLate), "a page left during the wait doesn't navigate the one now showing");

    private static void Check(Dictionary<string, int> allowed, IEnumerable<(string File, string What)> found, string because)
    {
        var (offenders, stale) = Against(allowed, found);
        offenders.Should().BeEmpty(because);
        stale.Should().BeEmpty("a fixed site comes off the wave-2b list (or its count is corrected)");
    }

    private delegate IEnumerable<string> Rule(ComponentSourceScanner.Method m, IReadOnlyDictionary<string, string> fields, ISet<string> services);

    private static List<(string File, string What)> Scan(Rule rule, bool raw = false) =>
        Components().SelectMany(c =>
        {
            var fields = Fields(c.Parts);
            var services = InjectedServices(c.Parts);
            return c.Parts.SelectMany(p => Methods(BlankGuardedBlocks(raw ? p.Raw : p.Code)))
                .Where(m => m.IsAsync)
                .SelectMany(m => rule(m, fields, services).Select(w => (c.File, $"{m.Name}: {w}")));
        }).ToList();

    // The stretch of a body from each await to the next one (or the end): what runs once that await has returned.
    private static IEnumerable<(int At, string Text)> AfterEachAwait(string body)
    {
        var awaits = Awaits(body);
        for (var i = 0; i < awaits.Count; i++)
        {
            var end = i + 1 < awaits.Count ? awaits[i + 1] : body.Length;
            var start = body.IndexOf(';', awaits[i]);   // the awaited statement itself
            if (start < 0 || start >= end) continue;
            yield return (awaits[i], body[start..end]);
        }
    }

    // A: guarded before an await, then a later await followed by a state change with no guard of its own.
    private static IEnumerable<string> NotRechecked(ComponentSourceScanner.Method m, IReadOnlyDictionary<string, string> fields, ISet<string> services)
    {
        var first = ForWhat().Match(m.Body);
        if (!first.Success) yield break;
        var awaits = Awaits(m.Body);
        if (!awaits.Any(a => a > first.Index)) yield break;   // checked only after the last wait: nothing to recheck
        foreach (var (at, text) in AfterEachAwait(m.Body).Where(s => s.At > first.Index))
        {
            var change = StateChange().Match(text);
            if (change.Success && !Currentness().IsMatch(text[..change.Index]) && !Currentness().IsMatch(GuardOf(m.Body, at)))
                yield return change.Value.Trim();
        }
    }

    // B: a field set from an awaited read on a service, with no guard between the read and the assignment. A first load
    // (OnInitializedAsync, which runs once) is left out.
    private static IEnumerable<string> Unsequenced(ComponentSourceScanner.Method m, IReadOnlyDictionary<string, string> fields, ISet<string> services)
    {
        if (m.Name is "OnInitializedAsync" || m.Name.EndsWith("<lambda>", StringComparison.Ordinal)) yield break;
        foreach (Match read in AwaitedRead().Matches(m.Body))
        {
            if (!services.Contains(read.Groups["svc"].Value) || !ReadCall().IsMatch(read.Groups["call"].Value)) continue;
            string? target = read.Groups["field"].Success ? read.Groups["field"].Value : null;
            var stmtEnd = m.Body.IndexOf(';', read.Index);
            if (stmtEnd < 0) continue;
            if (target is null && read.Groups["local"].Success)
            {
                // var x = await ...; then _field = x (or = x...) later
                var local = read.Groups["local"].Value;
                var use = Regex.Match(m.Body[stmtEnd..], @"\b(?<f>_\w+(?:\.\w+)?)\s*=\s*" + Regex.Escape(local) + @"\b", RegexOptions.None, TimeSpan.FromSeconds(1));
                if (!use.Success) continue;
                var between = m.Body[stmtEnd..(stmtEnd + use.Index)];
                if (Currentness().IsMatch(between) || Awaits(between).Count > 0 && Currentness().IsMatch(between)) continue;
                if (!fields.ContainsKey(use.Groups["f"].Value.Split('.')[0])) continue;
                yield return $"{use.Groups["f"].Value} = {local} ({read.Groups["svc"].Value}.{read.Groups["call"].Value})";
            }
            else if (target is not null && fields.ContainsKey(target.Split('.')[0]))
            {
                yield return $"{target} = await {read.Groups["svc"].Value}.{read.Groups["call"].Value}";
            }
        }
    }

    // C: a string field cleared after an await, where the method read it before that await, not under an if about it.
    // Only fields a text box binds to (@bind="_x"): the ones a user types into.
    private static IEnumerable<string> ClearedOverTyping(ComponentSourceScanner.Method m, IReadOnlyDictionary<string, string> fields, ISet<string> services) =>
        LateClears(m, fields.Where(f => f.Value.StartsWith("string", StringComparison.Ordinal) && Bound.Value.Contains(f.Key))
            .ToDictionary(f => f.Key, f => f.Value, StringComparer.Ordinal), _ => true);

    private static readonly Lazy<HashSet<string>> Bound = new(() =>
        Sources().SelectMany(s => BindTarget().Matches(s.Raw).Select(b => b.Groups["f"].Value)).ToHashSet(StringComparer.Ordinal));

    [GeneratedRegex(@"@bind(?:-Value)?\s*=\s*""(?<f>_\w+)""", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex BindTarget();

    // D: a row-key field (the open form) set to null after an await, where the method read it before.
    private static IEnumerable<string> ClosesAnotherForm(ComponentSourceScanner.Method m, IReadOnlyDictionary<string, string> fields, ISet<string> services) =>
        LateClears(m, fields, type => type is "Guid?" or "int?" or "long?");

    private static IEnumerable<string> LateClears(ComponentSourceScanner.Method m, IReadOnlyDictionary<string, string> fields, Func<string, bool> kind)
    {
        var awaits = Awaits(m.Body);
        if (awaits.Count == 0) yield break;
        foreach (Match clear in Clear().Matches(m.Body))
        {
            var f = clear.Groups["f"].Value;
            if (!fields.TryGetValue(f, out var type) || !kind(type)) continue;
            var lastAwait = awaits.LastOrDefault(a => a < clear.Index, -1);
            if (lastAwait < 0) continue;
            var fieldRef = new Regex(@"\b" + Regex.Escape(f) + @"\b", RegexOptions.None, TimeSpan.FromSeconds(1));
            var sentBy = m.Body.IndexOf(';', lastAwait);   // the awaited call's own arguments count as what was sent
            if (sentBy < 0 || sentBy > clear.Index) sentBy = lastAwait;
            if (!fieldRef.IsMatch(m.Body[..sentBy])) continue;   // not what was sent: a reset of something else
            if (Regex.IsMatch(GuardOf(m.Body, clear.Index), @"\bif\s*\([^;]*\b" + Regex.Escape(f) + @"\b", RegexOptions.None, TimeSpan.FromSeconds(1))) continue;
            if (Currentness().IsMatch(GuardOf(m.Body, clear.Index))) continue;
            yield return clear.Value.Trim();
        }
    }

    // E: Nav.NavigateTo after an await with no disposed or currentness check since.
    private static IEnumerable<string> NavigatesLate(ComponentSourceScanner.Method m, IReadOnlyDictionary<string, string> fields, ISet<string> services)
    {
        foreach (Match nav in NavigateTo().Matches(m.Body))
        {
            var lastAwait = m.Body.LastIndexOf("await ", nav.Index, StringComparison.Ordinal);
            if (lastAwait < 0) continue;
            var since = m.Body[lastAwait..nav.Index];
            if (HasDisposedCheck(since) || Currentness().IsMatch(since)) continue;
            if (since.Contains("=>", StringComparison.Ordinal)) continue;   // in a callback made after the await, run later
            yield return nav.Value.Trim();
        }
    }

    // The statement head before an offset: back to the previous `;`, `{` or `}` (an `if (...)` it sits under, unbraced).
    private static string GuardOf(string body, int index)
    {
        var start = body.LastIndexOfAny([';', '{', '}'], Math.Max(0, index - 1));
        return body[(start + 1)..index];
    }

    // Is the result still for what's open: the case (IsFor, an id compare), the newest load (a sequence), the page.
    [GeneratedRegex(@"\bIsFor\(|\bIsCurrent(?:For)?\(|\bCloseIf\(|\b\w*[Ss]eq\b\s*!=|!=\s*\w*[Ss]eq\b|\bmine\s*!=|\bStale\(\)|\bLeft\(\)|\bId\s*!=|!=\s*Id\b|\bId\s*==\s*\w+|_disposed\b|\bDisposed\b|IsCancellationRequested",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Currentness();

    // What tells a method its result is for one case or row (A's trigger): IsFor, a case-id compare, a session or load.
    [GeneratedRegex(@"\bIsFor\(|\bIsCurrent(?:For)?\(|\bId\s*!=|!=\s*Id\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex ForWhat();

    // A change to the component's state: an assignment to a field (or a field's member) other than a busy flag, or a
    // draft's Discard/Begin/Prefill.
    [GeneratedRegex(@"\b_\w+(?:\.\w+)*\s*(?:=(?!=)(?!\s*(?:true|false)\s*;)|\+=|-=)[^;]*;|\b_\w+\.(?:Discard|Begin|Prefill|Clear)\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex StateChange();

    [GeneratedRegex(@"(?:(?<field>_\w+(?:\.\w+)?)\s*=\s*|var\s+(?<local>\w+)\s*=\s*|\((?:[^()=]*)\)\s*=\s*)?\(?\s*await\s+(?<svc>\w+)\.(?<call>\w+)\s*(?:<[^>()]*>)?\(",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex AwaitedRead();

    [GeneratedRegex(@"^(?:Get|List|Find|Search|Preview|Evaluate|Resolve|Lookup|Load|Count|Describe|Build|Query|Fetch|Suggest|Matches|Overlap|Readiness|Linkable|Mentionable|SupersedeExposure|Labels|Peek)\w*$",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex ReadCall();

    [GeneratedRegex(@"\b(?<f>_\w+)\s*=\s*(?:""""|null|string\.Empty)\s*;", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Clear();

    [GeneratedRegex(@"\bNav\.NavigateTo\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex NavigateTo();
}
