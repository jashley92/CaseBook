using System.Reflection;
using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// C14 (BUG-596/597, BUG-377's class), widened by BUG-624: what the services read or send about a case is held to the
/// case's audience. Every read of a case table (Cases, and every table with a CaseId, found by reflection over
/// AppDbContext) in Application and Infrastructure passes one of the rules below, or its method is on the reviewed list
/// with why it's safe; and every notification that names a person is sent only to the people the audience filter lets
/// through. The web project doesn't use the database context except where listed. These checks read the source, so a
/// new unscoped read, a new table or an unfiltered notification fails here.
/// </summary>
public partial class CaseAudienceGateTests
{
    // The rules a read passes by itself:
    //   scoped: the statement goes through Scoped()/ForUser, or filters on the caller (== me), or on ids already visible;
    //   keyed: the statement is keyed by one case (CaseId == caseId, ...) and the method checks the caller can see it;
    //   admin: the method requires an administrator's permission first.
    // Reads that pass none of them, by file and enclosing method: how many there are, and why they're safe. A method with
    // more is an offender (a new read in a reviewed method is reviewed again); one with fewer comes off or down the list.
    private static readonly Dictionary<string, (int Reads, string Why)> Reviewed = new(StringComparer.Ordinal)
    {
        // Cases/CaseService.cs (the C14 list)
        ["CaseService.cs:NumberTakenAsync"] = (1, "a case number is unique across every case, seen or not (BUG-145); only a bool comes back"),
        ["CaseService.cs:SearchMatchesAsync"] = (9, "the ids come from the page of an already scoped list"),
        ["CaseService.cs:RefreshPartsAsync"] = (1, "after the scoped AnyAsync check for the same id"),
        ["CaseService.cs:CasesShowingAsync"] = (7, "the ids come from an already scoped search"),
        ["CaseService.cs:ClosingLinesAsync"] = (3, "the ids come from already scoped cases"),
        ["CaseService.cs:IsExerciseAsync"] = (1, "a bool for a case the caller has already loaded through scoping"),
        ["CaseService.cs:EnsureSameSideAsync"] = (1, "a bool for two cases the caller has already loaded through scoping"),
        ["CaseService.cs:SearchLinkableCasesAsync"] = (2, "the case's own exercise flag; the cases offered are read through Scoped"),
        ["CaseService.cs:GetPreviewAsync"] = (1, "after the scoped head read for the same id; related cases go through the scoped visibleIds"),
        ["CaseService.cs:MoveEvidenceAsync"] = (1, "whether the case moved to, read through Scoped just before, holds the same file"),
        ["CaseService.cs:EnsureEvidenceOnCaseAsync"] = (1, "private: its callers loaded the case with LoadTrackedAsync; the evidence must be on it"),
        ["CaseService.cs:ApplyFollowUpsAsync"] = (1, "private: its callers loaded the case with LoadTrackedAsync"),
        ["CaseService.cs:AnswerQuestionAsync"] = (1, "CAP-23, private: called from ApplyFollowUpsAsync, whose callers loaded the case with LoadTrackedAsync"),
        ["CaseService.cs:LinkedAsync"] = (1, "a bool; its callers checked both cases through Scoped"),
        ["CaseService.cs:SupersedeExposureAsync"] = (2, "after the scoped read of both cases (null unless both are visible)"),
        ["CaseService.cs:SupersedeAsync"] = (2, "after both cases are checked through Scoped and loaded with LoadTrackedAsync"),
        ["CaseService.cs:RemoveCaseLinkAsync"] = (1, "the link is removed only when both its cases are visible (the scoped count right after)"),
        ["CaseService.cs:ResolveAboutAsync"] = (3, "private: its caller loaded the case with LoadTrackedAsync; the target must be on that case"),
        ["CaseService.cs:MergeAppendedAsync"] = (1, "private: its caller loaded the case with LoadTrackedAsync"),
        ["CaseService.cs:EnsureQuestionAnsweredAsync"] = (1, "private: its callers loaded the task's case with LoadTrackedAsync"),
        ["CaseService.cs:AttachScreenshotAsync"] = (1, "CAP-26, private: its callers loaded the case with LoadTrackedAsync; the duplicate check reads only that case's evidence"),
        // Activity, administration, campaigns
        ["ActivityFeedService.cs:RecentAsync"] = (1, "an existence test only (audit rows under a number no case holds now, BUG-277); no case row comes back"),
        ["CaseOutcomeService.cs:ListAllAsync"] = (1, "how many closes recorded each outcome, for the administration list; no case named"),
        ["DataElementService.cs:ListAllAsync"] = (1, "which element keys any case references (delete is offered only where none does); no case named"),
        ["TeamService.cs:ListAllAsync"] = (1, "CAP-36: how many cases name each team, for the Teams page; a count per team, no case named"),
        ["CampaignService.cs:GetRollupAsync"] = (4, "the anchor is checked through ForUser; member ids come from ResolveMemberIdsAsync, visible ones only"),
        ["CampaignService.cs:ListAsync"] = (2, "the link graph is read whole, then cut to the cases ForUser returns; the exercise flags only drop edges"),
        ["CampaignService.cs:ResolveMemberIdsAsync"] = (2, "walks the whole link graph, then keeps the visible component only (ForUser), so a restricted case never bridges two"),
        // Case helpers and services called for a case already checked
        ["AfterClosure.cs:QueryAsync"] = (2, "its callers (ActivityFeedService, ReportService) checked the case through ForUser first"),
        // CAP-38: AnyUnnotifiedAsync reads through StandingAsync now.
        ["NotificationDeadlineService.cs:StandingAsync"] = (1, "safe by its callers only: AnyUnnotifiedAsync (StageGateEvaluator.BuildFactsAsync, which CaseService runs for a case it has already checked: CanSeeAsync / LoadTrackedAsync), ReportService's notification line, for the case it loaded for a report the caller may generate or preview, LessonsService's narrative draft, after its ForUser read of the same case, and EvaluateAsync with the clocks off (CAP-38 review), whose callers show a case they loaded through scoping; returns which jurisdiction codes are notified, nothing else of the case"),
        ["NotificationDeadlineService.cs:EvaluateAsync"] = (1, "safe by its callers only: the case overview (a case the workspace loaded through scoping), SetArchivedAsync (after LoadTrackedAsync) and ReportService's notification line (CAP-38, after its ForUser check)"),
        ["NotificationDeadlineService.cs:FreezeNoticeDuesAsync"] = (2, "a back-fill of notice deadlines (start-up, and CaseService for a case it has just saved); returns a count only"),
        ["NotificationDeadlineService.cs:RecheckUnreportedAsync"] = (1, "inside an administrator's save (the data elements page, a config import); rechecks every unreported case; returns the cases it left fully reported only for their 5513 to the SIEM (CAP-38 review), never to a page"),
        ["StageGateEvaluator.cs:BuildFactsAsync"] = (10, "the gates are evaluated through CaseService after CanSeeAsync / ForUser / LoadTrackedAsync for the case"),
        ["EvidenceService.cs:RecordTransferAsync"] = (1, "after LoadScopedAsync for the evidence; reads its own case's number"),
        ["EvidenceService.cs:GetCustodyAsync"] = (1, "the evidence's case is checked through ForUser before anything is returned"),
        ["EvidenceService.cs:CompleteUploadAsync"] = (1, "PROD-56: re-reads the record this person's own upload just wrote, after CheckCanUploadAsync scoped its case"),
        ["EvidenceService.cs:RecordPackageAsync"] = (1, "CAP-12: the files of a package OpenPackageAsync opened after its ForUser check, keyed by that case; it records the transfer once the bytes have gone, whatever the person's access is by then"),
        ["EvidenceService.cs:RecordAsync"] =(1, "PROD-59: the same file already in this case, keyed by the case every caller checked first (CheckCanUploadAsync); it names that case's own file"),
        ["EvidenceRoom.cs:UseAsync"] = (1, "PROD-55: the total size of all evidence, one number with no case or file in it (the storage limit check and Diagnostics)"),
        ["ReportService.cs:StoreAsync"] = (1, "private: its callers checked the case through ForUser"),
        ["ReportService.cs:ApproveCoreAsync"] = (1, "the report's case is checked through ForUser before anything else"),
        ["ReportService.cs:VerifyFileAsync"] = (1, "the report's case is checked through ForUser before anything else"),
        ["ReportService.cs:ExtrasAsync"] = (1, "private: its callers checked the case through ForUser"),
        ["ReportService.cs:LoadFullCaseAsync"] = (1, "private: its callers checked the case through ForUser first"),
        ["ReportService.cs:BuildLessonsModelAsync"] = (3, "private: its caller read the case through ForUser"),
        // Ids already scoped: a query over, or a list from, the caller's ForUser cases
        ["DashboardService.cs:PhaseAgingAsync"] = (1, "ids are a subquery over the ForUser cases"),
        ["NeedsActionService.cs:GetAsync"] = (8, "ids come from the ForUser cases"),
        ["PeriodHistory.cs:LoadAsync"] = (6, "its callers pass ids of their ForUser cases (DashboardService, ProgramReportService)"),
        ["ProgramReportService.cs:LoadAsync"] = (1, "ids are a subquery over the ForUser cases"),
        ["ProgramReportService.cs:ReviewsRecordedAsync"] = (1, "caseIds is LoadAsync's ForUser subquery"),
        ["VendorCasesService.cs:GetAsync"] = (1, "ids come from the ForUser cases"),
        ["IndicatorService.cs:SearchAsync"] = (1, "names are read for the case ids already shown (MatchAsync's ForUser rows)"),
        ["IndicatorService.cs:MatchAsync"] = (1, "CAP-27: occurrences are joined to the ForUser cases"),
        ["LessonsService.cs:GetRegisterAsync"] = (1, "joined to the ForUser cases"),
        ["FindService.cs:FindCoreAsync"] = (16, "caseIds is the ForUser case query; entity ids are read within it (CAP-22: FindAsync runs it, by word or by substring)"),
        ["FindService.cs:EditedEntriesFirstRecordedByAsync"] = (1, "caseIds is FindCoreAsync's ForUser case query"),
        ["FindService.cs:EditedNotesFirstWrittenByAsync"] = (1, "caseIds is FindCoreAsync's ForUser case query"),
        ["FindService.cs:ClosingLinesAsync"] = (3, "ids are FindAsync's visible case rows"),
        ["FindService.cs:ClosingBriefIdsAsync"] = (2, "ids are FindAsync's visible case ids"),
        ["DeskService.cs:GetAsync"] = (7, "ids come from the caller's own work (MyWork: scoped open cases, tasks, escalations)"),
        ["AccessLogService.cs:Filtered"] = (1, "CAP-32, private: the access log's filter for QueryAsync and WriteCsvAsync, which both require Administer first"),
        ["AccessLogService.cs:RecordAsync"] = (1, "the caller's own access rows (ActorUserId == actor), to fold a repeat view"),
        // Background jobs: no caller to scope for; who is told goes through ReminderAudience
        ["DueSoonActionItemScanner.cs:ScanAndNotifyAsync"] = (2, "a background scan of every case; who is told goes through ReminderAudience"),
        ["NotificationDeadlineScanner.cs:ScanAndNotifyAsync"] = (1, "a background scan of every case; who is told goes through ReminderAudience"),
        ["OverdueActionItemScanner.cs:ScanAndNotifyAsync"] = (2, "a background scan of every case; who is told goes through ReminderAudience"),
        ["StaleCaseScanner.cs:ScanAndNotifyAsync"] = (1, "a background scan of every case; who is told goes through ReminderAudience"),
        ["AgendaService.cs:GetFeedItemsAsync"] = (2, "one user's feed (a calendar feed token's owner, the digest): restricted cases are filtered inline for that user (BUG-401)"),
        ["PendingImportQueue.cs:WaitingForAsync"] = (1, "CAP-01: the digest's count for one reviewer; each restricted target's audience is judged through ReminderAudience, and only a count comes back"),
        ["CriticalAlertOutbox.cs:RetryDueAsync"] = (1, "the alert outbox retrying its own rows (a background job)"),
        // BUG-654: HeldEmails has a CaseId, so it's a case table; the sender keeps and drains its own rows (BUG-617)
        ["EmailSender.cs:HeldCountAsync"] = (1, "a count of the held mail, for the sender's own tests"),
        ["EmailSender.cs:HoldAsync"] = (1, "the count before holding one more (MaxHeld)"),
        ["EmailSender.cs:DrainHeldAsync"] = (3, "the drain reading and removing its own rows; a case's email is re-checked against its audience first"),
        ["EmailSender.cs:PutBackAsync"] = (1, "the drain putting one of its own rows back for a later try (BUG-653, BUG-659)"),
        ["EmailSender.cs:StillEntitledAsync"] = (1, "the case's restriction and team, to check a held email's recipients against its audience (BUG-654)"),
        ["HeldEmailSummary.cs:ReadAsync"] = (2, "CAP-04: Diagnostics' bounded count of the held mail and the oldest's time; no recipient, subject or case"),
        ["EvidenceKeyring.cs:EncryptedFileKeyIdAsync"] = (1, "PROD-57 review finding 3: before a new evidence key is made, every stored file's path and recorded size, to tell plain files from encrypted ones without opening them; its result is a key id or nothing"),
        ["EvidenceConversion.cs:RunAsync"] = (2, "PROD-57: the background encryption of files stored before, over every evidence file and report; it reads storage paths and hashes only, and its result is counts"),
        ["EvidenceIntegrityVerifier.cs:VerifyShareAsync"] = (2, "the evidence integrity sweep over every file (or a share of them, PROD-53); its result is counts and alerts, not case content"),
        ["RetentionReviewScanner.cs:CountAsync"] = (1, "CAP-10: the nightly retention count over every case; its result is two numbers (due, under hold), no case named"),
        ["AccessLogRetention.cs:PruneAsync"] = (2, "PROD-52: the nightly access-log prune deletes old rows and reads a case only for its legal hold; nothing is shown to anyone"),
        ["RowIntegrityVerifier.cs:Tables"] = (27, "the list of hashed tables the integrity check verifies, every row"),
        ["RowIntegrityVerifier.cs:ReplacedButCurrentAsync"] = (7, "the integrity check's version-lineage test over every row"),
        ["RowIntegrityVerifier.cs:HiddenAsync"] = (4, "the integrity check's hidden-version test over every row (BUG-634)"),
        // Start-up: migration back-fills and development seed data, before any request
        ["DevDataSeeder.cs:InitializeAsync"] = (1, "development seed data at start-up"),
        ["DevDataSeeder.cs:SeedModelShowcaseAsync"] = (1, "development seed data at start-up"),
        ["DevDataSeeder.cs:SeedComplianceShowcaseAsync"] = (3, "development seed data at start-up"),
        ["DevDataSeeder.cs:SeedHistoricalDemoAsync"] = (3, "development seed data at start-up"),
        ["ReportedJurisdictionsBackfill.cs:RunAsync"] = (1, "a start-up back-fill"),
        ["ReportedJurisdictionsBackfill.cs:WriteAsync"] = (1, "the start-up back-fill's audited write of one case (BUG-631)"),
        ["ReportedJurisdictionsBackfill.cs:RepairDamagedAsync"] = (1, "a start-up back-fill"),
        ["ReportedJurisdictionsBackfill.cs:KnownElementKeysAsync"] = (1, "a start-up back-fill"),
        ["ReportedJurisdictionsBackfill.cs:KeepElementsAsync"] = (1, "a start-up back-fill"),
        ["RowHashBackfill.cs:RunAsync"] = (8, "a start-up back-fill"),
    };

    // Notifications that don't go to a case's audience, with why.
    private static readonly Dictionary<string, string> NotAudience = new(StringComparer.Ordinal)
    {
        ["OnReclassifiedAsync"] = "goes to the configured Legal distribution and the shared channel, not to a person on the case",
        ["OnExecutiveReportAsync"] = "a program-wide quarterly report (no one case's), sent to the Managers (CaseNotifications.ManagersAsync)",
        ["OnRetentionReviewDueAsync"] = "CAP-10: counts only, no case named, to the configured Legal distribution (not a person on a case)",
    };

    // Web files that may use the database context, with why.
    private static readonly Dictionary<string, string> WebDbContext = new(StringComparer.Ordinal)
    {
        ["Components/Pages/Admin.razor"] = "the diagnostics tab: provider name, pending migrations, can-connect; no table read",
        ["Services/AdminHealth.cs"] = "Diagnostics and the overview's checks: can-connect and pending migrations, and the held-mail count (HeldEmailSummary); no table read",
        ["HealthChecks/DatabaseHealthCheck.cs"] = "the health endpoint's can-connect check; no table read",
        ["Program.cs"] = "start-up: migrations, seeding and back-fills, before any request",
        ["BackgroundJobs/RowHashUpgradeHostedService.cs"] = "the integrity upgrade moved out of start-up (BUG-644): records hashes, shows no case to anyone",
        ["Components/Shared/DeliveryHealthPanel.razor"] = "CAP-04: Diagnostics' delivery card counts the held emails (HeldEmailSummary); no case or recipient is read",
        ["Notifications/SmtpSignInStore.cs"] = "CAP-05: the relay sign-in saved in Administration (SmtpSignIns); no case table read",
        ["Secrets/StoredSecretStore.cs"] = "CAP-40: the chat webhook URL and SIEM token saved in Administration (StoredSecrets); no case table read",
        ["Secrets/StoredSecretAdminService.cs"] = "CAP-40: the secret cards' saves (StoredSecrets); no case table read",
        ["Secrets/TeamWebhookAdminService.cs"] = "CAP-36: a team's webhook card's saves (StoredSecrets) and the team's name (Teams); no case table read",
    };

    [Fact]
    public void The_case_tables_are_found_by_reflection()
    {
        var tables = CaseTables();
        tables.Should().Contain(["Cases", "Notes", "Evidence", "TimelineEntries", "ActionItems", "CaseEntities", "JurisdictionNotices", "Reports"]);
        tables.Count.Should().BeGreaterThan(25, "every table with a CaseId is a case table");
    }

    [Fact]
    public void Every_read_of_a_case_table_is_scoped_or_reviewed()
    {
        var found = Reads().ToList();
        found.Count.Should().BeGreaterThan(300, "the scan must find the services' reads of case tables");
        var unpassed = found.Where(r => r.Rule is null).ToList();

        var byMethod = unpassed.GroupBy(r => r.Key, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal);
        var dump = Environment.GetEnvironmentVariable("CB_SCAN_DUMP");
        if (!string.IsNullOrEmpty(dump)) File.WriteAllLines(dump, byMethod.Select(m => $"{m.Key} {m.Value.Count}"));

        var offenders = byMethod.Where(m => m.Value.Count > (Reviewed.TryGetValue(m.Key, out var r) ? r.Reads : 0))
            .SelectMany(m => m.Value.Select(r => $"{r.File}:{r.Line} {r.Method} ({r.Table})")).ToList();
        offenders.Should().BeEmpty("a read of a case table goes through Scoped()/ForUser, is keyed by a case the method checks, " +
            "is an administrator's, or is reviewed on the list above");

        var stale = Reviewed.Where(r => (byMethod.GetValueOrDefault(r.Key)?.Count ?? 0) < r.Value.Reads)
            .Select(r => $"{r.Key} (listed {r.Value.Reads}, found {byMethod.GetValueOrDefault(r.Key)?.Count ?? 0})").ToList();
        stale.Should().BeEmpty("a reviewed method with fewer unscoped reads than listed comes off (or down) the list");
    }

    [Fact]
    public void Every_notification_to_a_person_is_preceded_by_the_audience_filter()
    {
        var offenders = new List<string>();
        var seen = 0;
        foreach (var (file, lines, methods) in Sources("IncidentManager.Application"))
        {
            for (var i = 0; i < lines.Length; i++)
            {
                foreach (Match m in NotificationCall().Matches(lines[i]))
                {
                    seen++;
                    if (NotAudience.ContainsKey(m.Groups["name"].Value)) continue;
                    var start = methods.Where(x => x.Line <= i).Select(x => x.Line).DefaultIfEmpty(0).Max();
                    var body = string.Join('\n', lines[start..(i + 1)]);
                    var call = body.LastIndexOf(m.Value, StringComparison.Ordinal);
                    if (!AudienceFilter().IsMatch(body[..call]))
                        offenders.Add($"{file}:{i + 1} {Enclosing(methods, i)} -> {m.Groups["name"].Value}");
                }
            }
        }
        seen.Should().BeGreaterThan(10, "the scan must find the notification calls (CaseService and the scanners)");
        offenders.Should().BeEmpty("a notification naming a person goes only to the recipients the audience filter lets through");
    }

    [Fact]
    public void The_web_project_reads_cases_only_through_the_services()
    {
        var root = Path.Combine(RepoRoot(), "src", "IncidentManager.Web");
        var users = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
            .Where(f => (f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
                && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(f => DbContextUse().IsMatch(ComponentSourceScanner.StripComments(File.ReadAllText(f))))
            .Select(f => Path.GetRelativePath(root, f).Replace('\\', '/'))
            .ToList();
        users.Except(WebDbContext.Keys).Should().BeEmpty("a page or endpoint reads cases through a service, which scopes them");
        WebDbContext.Keys.Except(users).Should().BeEmpty("a listed file that no longer uses the context comes off the list");
    }

    [Fact]
    public void The_audience_filter_is_registered_for_injection()
    {
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        IncidentManager.Application.DependencyInjection.AddApplication(services);
        services.Should().Contain(d => d.ServiceType == typeof(IncidentManager.Application.Notifications.ReminderAudience),
            "CaseService takes the shared filter from DI, so it asks the directory of record (ITokenOwnerCheck)");
    }

    private sealed record Read(string File, int Line, string Method, string Table, string? Rule)
    {
        public string Key => $"{File}:{Method}";
    }

    // Every DbSet of Case, or of an entity with a CaseId.
    private static HashSet<string> CaseTables() =>
        typeof(AppDbContext).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType.IsGenericType && p.PropertyType.GetGenericTypeDefinition() == typeof(DbSet<>))
            .Where(p => p.PropertyType.GetGenericArguments()[0] is var t
                && (t == typeof(IncidentManager.Domain.Entities.Case) || t.GetProperty("CaseId") is not null))
            .Select(p => p.Name)
            .ToHashSet(StringComparer.Ordinal);

    private static IEnumerable<Read> Reads()
    {
        var sets = string.Join('|', CaseTables().Select(Regex.Escape));
        var read = new Regex($@"\b\w*(?:db|Db|context|ctx)\.(?<set>{sets})\b", RegexOptions.None, TimeSpan.FromSeconds(1));
        foreach (var project in new[] { "IncidentManager.Application", "IncidentManager.Infrastructure" })
        {
            foreach (var (file, lines, methods) in Sources(project))
            {
                for (var i = 0; i < lines.Length; i++)
                {
                    foreach (Match m in read.Matches(lines[i]))
                    {
                        var rest = lines[i][(m.Index + m.Length)..].TrimStart();
                        if (rest.StartsWith(".Add(", StringComparison.Ordinal) || rest.StartsWith(".AddRange(", StringComparison.Ordinal)
                            || rest.StartsWith(".Remove(", StringComparison.Ordinal) || rest.StartsWith(".RemoveRange(", StringComparison.Ordinal)
                            || rest.StartsWith(';')) continue;   // a write
                        var start = methods.Where(x => x.Line <= i).Select(x => x.Line).DefaultIfEmpty(0).Max();
                        var (from, to) = Statement(lines, start, i);
                        var statement = string.Join('\n', lines[from..(to + 1)]);
                        var before = string.Join('\n', lines[start..(i + 1)]);
                        var whole = string.Join('\n', lines[start..(to + 1)]);
                        var rule = Scoped().IsMatch(statement) ? "scoped"
                            : Keyed().IsMatch(statement) && Checked().IsMatch(whole) ? "keyed"
                            : Admin().IsMatch(before) ? "admin"
                            : null;
                        yield return new Read(file, i + 1, Enclosing(methods, i), m.Groups["set"].Value, rule);
                    }
                }
            }
        }
    }

    // The statement around line i: back to the end of the one before (at most 6 lines), on to its semicolon (at most 14).
    private static (int From, int To) Statement(string[] lines, int methodStart, int i)
    {
        var to = i;
        while (!lines[to].TrimEnd().EndsWith(';') && to < i + 14 && to + 1 < lines.Length) to++;
        var from = i;
        while (from > methodStart && from > i - 6 && !lines[from - 1].TrimEnd().EndsWith(';') && !lines[from - 1].TrimEnd().EndsWith('{')
            && !lines[from - 1].TrimEnd().EndsWith('}')) from--;
        return (from, to);
    }

    private static IEnumerable<(string File, string[] Lines, List<(int Line, string Name)> Methods)> Sources(string project)
    {
        var root = Path.Combine(RepoRoot(), "src", project);
        foreach (var path in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            if (path.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)) continue;
            var lines = ComponentSourceScanner.StripComments(File.ReadAllText(path)).Split('\n');
            var methods = new List<(int, string)>();
            for (var i = 0; i < lines.Length; i++)
                if (MethodStart().Match(lines[i]) is { Success: true } m) methods.Add((i, m.Groups["name"].Value));
            yield return (Path.GetFileName(path), lines, methods);
        }
    }

    private static string Enclosing(List<(int Line, string Name)> methods, int line) =>
        methods.Where(m => m.Line <= line).Select(m => m.Name).LastOrDefault() ?? "?";

    private static string RepoRoot() => ComponentSourceScanner.RepoRoot();

    [GeneratedRegex(@"^    (?:public|private|internal|protected)\b[^=;(]*?\s(?<name>\w+)(?:<[^>]*>)?\s*\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex MethodStart();

    [GeneratedRegex(@"Scoped\(|\.ForUser\(|== me\b|\bvisible\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Scoped();

    [GeneratedRegex(@"\b(?:CaseId|TargetCaseId) == (?:caseId|id|c\.Id|report\.CaseId|evidence\.CaseId|eid)\b|\.Id == (?:evidenceId|reportId|eid|entityId)\b", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Keyed();

    [GeneratedRegex(@"Scoped\(|\.ForUser\(|CanSeeAsync\(|LoadTrackedAsync\(|LoadWithNoticesAsync\(|LoadScopedAsync\(|LoadCaseTrackedAsync\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Checked();

    [GeneratedRegex(@"Require<|Has\(Permission\.Administer\)", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Admin();

    [GeneratedRegex(@"\b_?notifications\??\.(?<name>On\w+Async)\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex NotificationCall();

    [GeneratedRegex(@"RecipientsAsync\(|\baudience\.\w+Async\(", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex AudienceFilter();

    [GeneratedRegex(@"\bAppDbContext\b|\bIAppDbContextFactory\b|\bIDbContextFactory<", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex DbContextUse();
}
