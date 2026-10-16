using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;
using static IncidentManager.UnitTests.ComponentSourceScanner;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-603 (C8): every UI handler that changes server state ignores a second invocation while the first runs (a
/// double-click, Enter and a click, two shortcuts). Unguarded, the second attempt saved twice, sent a test message twice,
/// recorded a second custody "Viewed", or came back refused ("someone else changed the case") over the first one's save.
/// This scan finds each component method that awaits a write on an injected service and fails unless the method, or the
/// wrapper that calls it, returns early while a run is under way: <c>InFlight.Run</c>, an <c>if (_busy) return; _busy =
/// true;</c> pair, or <c>if (!_set.Add(key)) return;</c>.
/// </summary>
/// <remarks>What it can't see: a write reached only through a lambda (a confirm's callback, which RunConfirm takes once);
/// a write made through a non-injected object; a guard that is a disabled button alone (markup, which Enter bypasses).</remarks>
public partial class InFlightGuardTests
{
    // Wave 2b: the sites in files this wave doesn't own, by file, with how many. Each owner wraps them in InFlight (or a
    // guard) and takes the entry off; a fixed site left listed fails the stale check below.
    private static readonly Dictionary<string, int> Allowed = new(StringComparer.Ordinal)
    {
        // wave 2b, U1 (timeline, notes)
        ["Pages/CaseTabs/CaseTimelineTab.razor"] = 2,   // SaveCite (Cases.CiteEvidenceAsync); MoveStep (Cases.MoveEventStepAsync)
        // wave 2b, U4 (pages, admin, other shared)
        ["Pages/AccountApiTokens.razor"] = 1,   // Revoke (Tokens.RevokeAsync)
        ["Pages/Admin.razor"] = 5,   // SendTest (Email.SendTestAsync); SendTestChat (Chat.SendTestAsync); SendSiemTest (SiemTest.SendTestAsync); OnLogoSelected (Branding.SaveLogoAsync); RemoveLogo (Brandi...
        ["Pages/AdminApiTokens.razor"] = 1,   // Revoke (Tokens.RevokeAsync)
        ["Pages/AdminGates.razor"] = 1,   // DeleteGate (Gates.DeleteAsync)
        ["Pages/AdminRoles.razor"] = 4,   // SaveRoleCore (Roles.CreateRoleAsync, Roles.UpdateRoleAsync); DeleteRole (Roles.DeleteRoleAsync); AddMappingCore (Roles.AddMappingAsync); RemoveMapping (Roles.Re...
        ["Pages/AdminTemplates.razor"] = 1,   // DeleteTemplate (Templates.DeleteAsync)
        ["Pages/CaseImport.razor"] = 2,   // ReopenStuck (Import.ReopenStuckAsync); Reject (Import.RejectPendingAsync)
        ["Pages/CaseTabs/CaseReportTab.razor"] = 1,   // ApproveReport (Reports.ApproveAsync)
        ["Pages/CaseTabs/CaseReviewTab.razor"] = 1,   // ApproveReport (Reports.ApproveAsync)
        ["Pages/Cases.razor"] = 1,   // DeleteView (Views.DeleteAsync)
        ["Shared/ReportProfilesEditor.razor"] = 1,   // Delete (Profiles.DeleteAsync)
        ["Shared/ReportTemplateLibrary.razor"] = 3,   // Replace (Templates.ReplaceFileAsync); ShowHere (Access.RecordArtifactAsync); SaveRename (Templates.RenameAsync)
        ["Shared/UndeliveredAlertBanner.razor"] = 1,   // Dismiss (Alerts.DismissAsync)
    };

    [Fact]
    public void Every_handler_that_writes_ignores_a_second_invocation_while_it_runs()
    {
        var (offenders, stale) = Against(Allowed, Unguarded());
        offenders.Should().BeEmpty("a handler that writes runs once at a time (InFlight.Run, or an early return while busy)");
        stale.Should().BeEmpty("a fixed site comes off the wave-2b list (or its count is corrected)");
    }

    [Fact]
    public void The_scan_sees_the_workspace_acts_and_their_guards()
    {
        // A guard on the guard: the workspace's acts are writes, each guarded, and a removed guard is seen.
        var ws = Components().Single(c => c.File == "Pages/CaseWorkspace.razor");
        Writers(ws.Parts).Select(w => w.Name).Should().Contain(["AssignToMeCore", "SetLegalHoldCore", "SetArchivedCore", "OpenShot", "TogglePin"]);
        Unguarded().Where(u => u.File == "Pages/CaseWorkspace.razor").Should().BeEmpty();
        var unguardedCopy = ws.Parts.Select(p => p with { Code = p.Code.Replace("_assigning.Run(AssignToMeCore)", "AssignToMeCore()", StringComparison.Ordinal) }).ToList();
        UnguardedIn("Pages/CaseWorkspace.razor", unguardedCopy).Should().Contain(u => u.What.StartsWith("AssignToMeCore", StringComparison.Ordinal));
    }

    private static IEnumerable<(string File, string What)> Unguarded() =>
        Components().SelectMany(c => UnguardedIn(c.File, c.Parts)).ToList();

    private static IEnumerable<(string File, string What)> UnguardedIn(string file, IReadOnlyList<Source> parts)
    {
        var methods = parts.SelectMany(p => Methods(p.Code)).Where(m => !m.Name.EndsWith("<lambda>", StringComparison.Ordinal)).ToList();
        foreach (var w in Writers(parts))
        {
            if (Guarded(w, methods, depth: 0)) continue;
            yield return (file, $"{w.Name} ({string.Join(", ", w.Writes)})");
        }
    }

    private sealed record Writer(string Name, ComponentSourceScanner.Method Method, IReadOnlyList<string> Writes);

    // The methods that await a write on an injected service (a call whose name isn't a read's).
    private static IEnumerable<Writer> Writers(IReadOnlyList<Source> parts)
    {
        var services = InjectedServices(parts);
        if (services.Count == 0) yield break;
        foreach (var m in parts.SelectMany(p => Methods(p.Code)))
        {
            // A sync method awaits only inside a lambda (a confirm callback, which RunConfirm takes once).
            if (!m.IsAsync || m.Name.EndsWith("<lambda>", StringComparison.Ordinal) || NotAHandler().IsMatch(m.Name)) continue;
            var writes = AwaitedCall().Matches(m.Body)
                .Where(c => services.Contains(c.Groups["svc"].Value) && !Read().IsMatch(c.Groups["call"].Value))
                .Select(c => $"{c.Groups["svc"].Value}.{c.Groups["call"].Value}")
                .Distinct(StringComparer.Ordinal).ToList();
            if (writes.Count > 0) yield return new Writer(m.Name, m, writes);
        }
    }

    // Guarded itself (before its first await), or called only from a guarded wrapper.
    private static bool Guarded(Writer w, IReadOnlyList<ComponentSourceScanner.Method> methods, int depth) =>
        HasOwnGuard(w.Method.Body) || (depth < 3 && Callers(w.Name, methods).ToList() is { Count: > 0 } callers
            && callers.All(c => HasOwnGuard(c.Body) || RunsThroughInFlight(c.Body, w.Name)
                || Guarded(new Writer(c.Name, c, []), methods, depth + 1)));

    private static IEnumerable<ComponentSourceScanner.Method> Callers(string name, IReadOnlyList<ComponentSourceScanner.Method> methods)
    {
        var call = new Regex(@"(?<![\w.])" + Regex.Escape(name) + @"\b(?!\s*=)", RegexOptions.None, TimeSpan.FromSeconds(1));
        return methods.Where(m => m.Name != name && call.IsMatch(m.Body));
    }

    private static bool RunsThroughInFlight(string body, string name) =>
        Regex.IsMatch(body, @"\.Run\(\s*(?:\(\)\s*=>\s*)?" + Regex.Escape(name) + @"\b", RegexOptions.None, TimeSpan.FromSeconds(1));

    // `if (... _flag ...) return;` with `_flag = true;` after it, or `if (!_set.Add(...)) return;`, or `X.Run(` as the
    // body, all before the first await.
    private static bool HasOwnGuard(string body)
    {
        var head = Awaits(body) is { Count: > 0 } a ? body[..a[0]] : body;
        if (InFlightRun().IsMatch(head) || SetGuard().IsMatch(head)) return true;
        foreach (Match g in EarlyReturn().Matches(head))
        {
            foreach (Match f in Flag().Matches(g.Groups["cond"].Value))
                if (Regex.IsMatch(head[g.Index..], @"\b" + Regex.Escape(f.Value) + @"\s*=\s*(?:true|[^;=]+;)", RegexOptions.None, TimeSpan.FromSeconds(1)))
                    return true;
        }
        return false;
    }

    // What a handler isn't: a lifecycle method, a load, a live refresh, a teardown.
    [GeneratedRegex(@"^(?:On(?:Initialized|ParametersSet|AfterRender)\w*|SetParametersAsync|Reload\w*|Load\w*|Refresh\w*|ApplyChangeAsync|Dispose\w*|UndoLate\w*)$",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex NotAHandler();

    [GeneratedRegex(@"\bawait\s+(?:[\w.]*\.)?(?<svc>\w+)\.(?<call>\w+)\s*(?:<[^>()]*>)?\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex AwaitedCall();

    // C8's enumeration (c8scan): what a call that only reads is named like.
    [GeneratedRegex(@"^(?:Get|List|Find|Load|Search|Preview|Count|Can|Is|Has|Build|Describe|Read|Query|Resolve|Check|Lookup|Render|Compute|Evaluate|Peek|Suggest|Probe|Validate|Explain|Summar|Recent|Pinned|Mine|Default|Dues|Overlap|Feed|For|Status|Health|Diff|Verify|Snapshot|Fetch|Parse|Open(?!ed)|Download|Export|Report|History|Audit|Watching|Who|Effective|Lines|Readiness|Notify|Notice|Deadline|Timeline|Workload|Overview|Coverage|Program|Candidates|Matches|Options|Linkable|Directory|Members|Users|Roles|Templates|Profiles|Settings|Keymap|Brief|Campaign|Indicators|Agenda|Desk|Queue|Pending|Job|Mentionable|SupersedeExposure|Authorize|Labels|LastViewed|Changes|Refresh|Compose|Fill|InvokeAsync)",
        RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Read();

    [GeneratedRegex(@"\b_?\w+\.Run\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex InFlightRun();

    [GeneratedRegex(@"if\s*\(\s*!\s*_\w+\.(?:Add|TryAdd)\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex SetGuard();

    [GeneratedRegex(@"if\s*\((?<cond>(?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)\s*(?:\{\s*)?return\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex EarlyReturn();

    [GeneratedRegex(@"\b_\w+\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Flag();
}
