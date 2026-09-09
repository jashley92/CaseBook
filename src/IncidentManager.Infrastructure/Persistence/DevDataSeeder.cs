using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// Applies migrations and, on an empty database, seeds representative demo cases so the app,
/// dashboards, and integration tests have realistic data (and a populated audit chain).
/// </summary>
public static class DevDataSeeder
{
    public static async Task InitializeAsync(AppDbContext db, IClock clock, bool seedDemoData, CancellationToken ct = default)
    {
        await db.Database.MigrateAsync(ct);

        // Starter case templates (E-06) ship in every environment on first run — they're ordinary editable
        // reference data, so admins can rename, extend, or delete them. Seeded only when none exist yet.
        await SeedStarterTemplatesAsync(db, clock, ct);

        // Default stage gates (C-07) likewise ship on first run as editable reference data. The Breach and
        // close gates carry the original C-04 breach-readiness intent out of the box.
        await SeedDefaultStageGatesAsync(db, clock, ct);

        // Starter report profiles (E-28): an "Executive summary" and a "Full examiner pack" so a case can
        // pick a section layout out of the box. Editable/admin-managed reference data; seeded only if empty.
        await SeedDefaultReportProfilesAsync(db, clock, ct);

        // Data-element reference set (X-03): the thirteen categories formerly baked into the enum, now
        // admin-managed reference data seeded on first run (codes are the original enum bit values).
        await SeedDataElementsAsync(db, clock, ct);

        if (!seedDemoData || await db.Cases.AnyAsync(ct))
            return;

        await SeedAsync(db, clock, ct);
    }

    /// <summary>
    /// Seeds two starter report profiles (E-28): a leadership-facing "Executive summary" (narrative only)
    /// and a "Full examiner pack" (every section, pinned so it stays complete even if the global default is
    /// later trimmed). Ordinary editable reference data; seeded only when none exist.
    /// </summary>
    public static async Task SeedDefaultReportProfilesAsync(AppDbContext db, IClock clock, CancellationToken ct = default)
    {
        if (await db.ReportProfiles.AnyAsync(ct)) return;

        var now = clock.UtcNow;

        db.ReportProfiles.AddRange(
            new ReportProfile
            {
                Name = "Executive summary",
                Description = "Leadership one-pager: narrative sections only, no timelines or appendix.",
                IsActive = true, SortOrder = 1, CreatedBy = "system", CreatedAtUtc = now,
                SectionLayout = "Summary,BusinessImpact,Outcome," +
                                "!EventTimeline,!InvestigationTimeline,!SystemsReviewed,!Recommendations,!Appendix"
            },
            new ReportProfile
            {
                Name = "Full examiner pack",
                Description = "Every section in default order — the complete record for an examiner / DFS pack.",
                IsActive = true, SortOrder = 2, CreatedBy = "system", CreatedAtUtc = now,
                SectionLayout = "Summary,BusinessImpact,EventTimeline,InvestigationTimeline," +
                                "SystemsReviewed,Recommendations,Outcome,Appendix"
            });

        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Seeds the built-in data-element reference set (X-03) on first run — the thirteen categories the app
    /// formerly hard-coded as a <c>[Flags]</c> enum, now editable/admin-managed reference data keyed by a
    /// stable <c>Key</c> (the value a case stores and the canonical hashes). Seeded only when none exist;
    /// admins may then rename / reorder / archive / add.
    /// </summary>
    public static async Task SeedDataElementsAsync(AppDbContext db, IClock clock, CancellationToken ct = default)
    {
        if (await db.DataElements.AnyAsync(ct)) return;

        var now = clock.UtcNow;
        db.DataElements.AddRange(DataElementCatalog.Defaults.Select(s => new DataElement
        {
            Key = s.Key,
            Label = s.Label,
            SortOrder = s.SortOrder,
            IsActive = true,
            IsSystem = true,
            CreatedBy = "system",
            CreatedAtUtc = now
        }));

        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Seeds a small library of common SOC playbooks so the New Case picker and Apply-playbook dialog
    /// have content out of the box. Each step's hour offset drives the due date of the action item it
    /// seeds; owner hints are left blank so seeded items fall to the case owner (the CaseBook default).
    /// </summary>
    public static async Task SeedStarterTemplatesAsync(AppDbContext db, IClock clock, CancellationToken ct = default)
    {
        if (await db.CaseTemplates.AnyAsync(ct)) return;

        var now = clock.UtcNow;

        CaseTemplate Template(string name, string desc, Classification cls, Severity sev, string dataTypes,
            string summary, int order, params (string Title, string? Note, int? DueHours)[] steps)
        {
            var t = new CaseTemplate
            {
                Name = name, Description = desc, IsActive = true, SortOrder = order,
                DefaultClassification = cls, DefaultSeverity = sev,
                DefaultDataTypes = dataTypes, SummaryBoilerplate = summary,
                CreatedBy = "system", CreatedAtUtc = now
            };
            var i = 0;
            foreach (var s in steps)
                t.Steps.Add(new CaseTemplateStep
                {
                    TemplateId = t.Id, Order = i++, Title = s.Title, Description = s.Note, DueOffsetHours = s.DueHours
                });
            return t;
        }

        db.CaseTemplates.AddRange(
            Template("Phishing wave",
                "Credential-harvest or malware-delivery phishing campaign.",
                Classification.Incident, Severity.Medium, "Credentials; potential NPI",
                "Suspected phishing campaign. Scope of recipients and click-through under assessment.", 1,
                ("Identify all recipients of the phishing message", "Pull the distribution from the mail gateway.", 4),
                ("Preserve the message and headers as evidence", null, 4),
                ("Block the sender, URL, and file hash at mail and proxy", null, 8),
                ("Reset credentials for anyone who clicked or entered them", null, 8),
                ("Hunt for post-delivery execution and suspicious authentications", null, 24),
                ("Draft the user-awareness follow-up", null, 48)),

            Template("Ransomware",
                "Encryption / extortion event on one or more endpoints or servers.",
                Classification.Incident, Severity.High, "Potential NPI; business data",
                "Suspected ransomware event. Scope of encryption and initial access under assessment.", 2,
                ("Isolate affected hosts from the network", "Contain before spread; preserve for forensics.", 2),
                ("Identify patient zero and the initial access vector", null, 8),
                ("Preserve volatile evidence and ransom notes", null, 4),
                ("Determine encryption scope and affected data", null, 12),
                ("Validate backups and test a restore", null, 24),
                ("Engage the incident-response retainer / carrier", null, 8),
                ("Assess regulatory notification obligations", null, 48),
                ("Eradicate persistence and reset exposed credentials", null, 48),
                ("Recover systems from clean backups", null, 72)),

            Template("BEC / wire fraud",
                "Business email compromise or fraudulent payment-change request.",
                Classification.Incident, Severity.High, "Financial; credentials; NPI",
                "Suspected business email compromise. Account access and any attempted transfer under assessment.", 3,
                ("Confirm the fraudulent request through an out-of-band channel", null, 2),
                ("Reset the compromised mailbox credentials and revoke sessions", null, 4),
                ("Review mailbox rules, forwarding, and OAuth grants", "Attackers hide with auto-forward / delete rules.", 4),
                ("Contact the bank to recall or hold any transfer", null, 2),
                ("Pull sign-in and audit logs for the affected accounts", null, 8),
                ("Notify affected finance staff and leadership", null, 8),
                ("Assess exposure of any data in the mailbox", null, 48)),

            Template("Lost / stolen device",
                "Misplaced or stolen laptop, phone, or removable media.",
                Classification.AdverseEvent, Severity.Medium, "Potential NPI on device",
                "Reported lost or stolen device. Encryption status and data exposure under assessment.", 4,
                ("Confirm the device identity and last-known custody", null, 4),
                ("Remote-lock or wipe the device via MDM", null, 4),
                ("Verify disk encryption status at last check-in", null, 8),
                ("Disable the user's sessions and rotate credentials if warranted", null, 8),
                ("Assess what data resided on the device", null, 24)));

        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Seeds the default stage gates (C-07) so escalation/closure completeness is enforced out of the box.
    /// The Breach and close gates carry the original C-04 breach-readiness field set. Editable reference
    /// data — admins can retune, disable, or delete them. Seeded only when none exist yet.
    /// </summary>
    public static async Task SeedDefaultStageGatesAsync(AppDbContext db, IClock clock, CancellationToken ct = default)
    {
        if (await db.StageGates.AnyAsync(ct)) return;

        var now = clock.UtcNow;

        StageGate Gate(StageGateTrigger trigger, string name, string desc,
            params (GateRequirementKind Kind, string? CheckKey, string? Label, bool Blocking)[] reqs)
        {
            var g = new StageGate
            {
                Trigger = trigger, Name = name, Description = desc, IsActive = true,
                CreatedBy = "system", CreatedAtUtc = now
            };
            var i = 0;
            foreach (var r in reqs)
                g.Requirements.Add(new StageGateRequirement
                {
                    GateId = g.Id, Order = i++, Kind = r.Kind, CheckKey = r.CheckKey,
                    Label = r.Label ?? (r.CheckKey is { } k ? GateCheckRegistry.Label(k) : ""),
                    IsBlocking = r.Blocking
                });
            return g;
        }

        (GateRequirementKind, string?, string?, bool) Check(string checkKey, bool blocking = true)
            => (GateRequirementKind.MachineCheck, checkKey, null, blocking);
        (GateRequirementKind, string?, string?, bool) Attest(string label, bool blocking = true)
            => (GateRequirementKind.Attestation, null, label, blocking);

        db.StageGates.AddRange(
            Gate(StageGateTrigger.PromoteToAdverseEvent, "Promotion readiness",
                "Minimum footing before a Complex Event enters the formal ladder.",
                Check(GateCheckKeys.SummaryPresent)),

            Gate(StageGateTrigger.EscalateToIncident, "Incident readiness",
                "Basic investigative footing before declaring an Incident.",
                Check(GateCheckKeys.SummaryPresent),
                Check(GateCheckKeys.AtLeastOneEntity),
                Check(GateCheckKeys.IncidentCommanderAssigned, blocking: false)),

            Gate(StageGateTrigger.EscalateToBreach, "Breach readiness",
                "The regulatory determination fields the report and compliance bundle depend on (C-04).",
                Check(GateCheckKeys.SummaryPresent),
                Check(GateCheckKeys.AffectedIndividualsCountSet),
                Check(GateCheckKeys.DataElementsSet),
                Check(GateCheckKeys.AffectedStatesSet),
                Check(GateCheckKeys.AtLeastOneMaliciousEntity, blocking: false),
                Attest("Impact assessment reviewed with leadership / Legal")),

            Gate(StageGateTrigger.CloseCase, "Closure readiness",
                "A defensible, complete record before the case is closed (C-04).",
                Check(GateCheckKeys.SummaryPresent),
                Check(GateCheckKeys.AtLeastOneReport, blocking: false),
                Attest("Post-incident review complete"),
                Attest("Evidence preserved and chain of custody complete")));

        await db.SaveChangesAsync(ct);
    }

    private static AppUser NewUser(string sid, string displayName, string email, string rolesCsv, DateTimeOffset now) =>
        new()
        {
            Sid = sid,
            DisplayName = displayName,
            UserPrincipalName = email,
            Email = email,
            RolesCsv = rolesCsv,
            LastSeenUtc = now
        };

    public static async Task SeedAsync(AppDbContext db, IClock clock, CancellationToken ct = default)
    {
        const string actor = "system";
        var now = clock.UtcNow;

        // The SOC team, mirrored as they would be from AD (E-22). Populates the directory so ids resolve
        // to names in the audit view / activity feed and the assignment picker has real people. Ids match
        // the assignees used below (ic1 / analyst1). The dev sign-in user also self-populates at runtime.
        db.Users.AddRange(
            NewUser("S-1-5-21-DEV-1001", "Dev Analyst", "dev.analyst@contoso-insurance.example",
                "Analyst,IncidentCommander,Manager,LegalPrivacy,SysAdmin", now),
            NewUser("ic1", "Ivy Commander", "ivy.commander@contoso-insurance.example", "IncidentCommander", now),
            NewUser("analyst1", "Alex Analyst", "alex.analyst@contoso-insurance.example", "Analyst", now),
            NewUser("analyst2", "Robin Reyes", "robin.reyes@contoso-insurance.example", "Analyst", now),
            NewUser("mgr1", "Morgan Manager", "morgan.manager@contoso-insurance.example", "Manager", now),
            NewUser("legal1", "Lee Privacy", "lee.privacy@contoso-insurance.example", "LegalPrivacy", now),
            NewUser("admin1", "Sam Admin", "sam.admin@contoso-insurance.example", "SysAdmin", now));
        await db.SaveChangesAsync(ct);

        // Case 1 — internal phishing, escalated to Breach with a Legal referral.
        var c1 = Case.Open(2026, 1, "Phishing Wave", "Credential-phishing wave targeting Finance",
            Classification.AdverseEvent, Severity.Medium, CaseOrigin.InternalDetection, actor, now.AddDays(-6));
        c1.DetectionCaseId = "SIEM-40122";
        c1.Summary = "Multiple finance users received look-alike O365 login prompts.";
        c1.DataTypesInvolved = "Credentials; potential NPI";
        db.Cases.Add(c1);
        await db.SaveChangesAsync(ct);

        c1.TimelineEntries.Add(new TimelineEntry
        {
            CaseId = c1.Id, Kind = TimelineKind.Event, OccurredAtUtc = now.AddDays(-6), Type = TimelineEntryType.Detection,
            Description = "12 inbound look-alike domains delivered O365 phishing lures; 3 finance users clicked.",
            Source = "SIEM", CreatedBy = actor, CreatedAtUtc = now.AddDays(-6)
        });
        c1.TimelineEntries.Add(new TimelineEntry
        {
            CaseId = c1.Id, Kind = TimelineKind.Investigation, OccurredAtUtc = now.AddDays(-5).AddHours(2),
            Type = TimelineEntryType.Analysis,
            Description = "Reviewed mailbox audit logs; confirmed one session established from a foreign ASN.",
            Source = "analyst1", CreatedBy = actor, CreatedAtUtc = now.AddDays(-5).AddHours(2)
        });
        c1.Notes.Add(new AnalystNote
        {
            CaseId = c1.Id, Body = "Reset credentials for affected users; pulled mailbox audit logs.",
            CreatedBy = actor, CreatedAtUtc = now.AddDays(-6)
        });
        c1.Assign("ic1", "Ivy Commander", CaseAssignmentRole.IncidentCommander, actor, now.AddDays(-6));
        c1.Assign("analyst1", "Alex Analyst", CaseAssignmentRole.Analyst, actor, now.AddDays(-6));
        c1.ChangePhase(CasePhase.Containment, "Isolated affected mailboxes", actor, now.AddDays(-5));
        await db.SaveChangesAsync(ct);

        c1.Reclassify(Classification.Incident, "Confirmed successful credential capture", actor, now.AddDays(-5));
        c1.ChangeSeverity(Severity.High, "Confirmed unauthorized mailbox access", actor, now.AddDays(-5));
        c1.Reclassify(Classification.Breach, "Evidence of mailbox access to files containing NY resident NPI", actor, now.AddDays(-4));
        c1.ChangeSeverity(Severity.Critical, "NY resident NPI confirmed exposed", actor, now.AddDays(-4));
        c1.ReferToLegal(actor, "privacy@contoso-insurance.example", "NY resident NPI potentially accessed — NYDFS Part 500 relevance.", now.AddDays(-4));
        c1.ActionItems.Add(new ActionItem
        {
            CaseId = c1.Id, Title = "Provide affected-user list to Legal", Owner = "ic1",
            DueAtUtc = now.AddDays(-2), Status = ActionItemStatus.Done, CompletedAtUtc = now.AddDays(-3),
            CreatedBy = actor, CreatedAtUtc = now.AddDays(-4)
        });

        // Entities / IOCs and the relationships between them (the investigation graph).
        var acct = c1.AddEntity(EntityType.Account, "CONTOSO\\jdoe", "Jane Doe (Finance)",
            EntityDisposition.Unknown, "Mailbox accessed by the attacker.", "SIEM", actor, now.AddDays(-5));
        var host = c1.AddEntity(EntityType.Host, "FIN-WKS-07", "Finance workstation",
            EntityDisposition.Benign, "Endpoint the affected user logged in from.", "SIEM", actor, now.AddDays(-5));
        var ip = c1.AddEntity(EntityType.IpAddress, "203.0.113.66", "Foreign ASN egress",
            EntityDisposition.Malicious, "Source of the unauthorized mailbox session.", "SIEM", actor, now.AddDays(-5));
        var url = c1.AddEntity(EntityType.Url, "https://o365-secure-login.contoso-insurance.example.attacker.test",
            "Phishing lure", EntityDisposition.Malicious, "Credential-harvesting page from the lure emails.",
            "analyst1", actor, now.AddDays(-6));
        c1.AddEntity(EntityType.FileHash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Lure attachment (SHA-256)", EntityDisposition.Suspicious, null, "VirusTotal", actor, now.AddDays(-6));

        c1.LinkEntities(acct.Id, url.Id, EntityRelationshipType.Accessed, "User submitted credentials to the lure.", actor, now.AddDays(-6));
        c1.LinkEntities(acct.Id, host.Id, EntityRelationshipType.LoggedInTo, null, actor, now.AddDays(-5));
        c1.LinkEntities(url.Id, ip.Id, EntityRelationshipType.ResolvedTo, null, actor, now.AddDays(-5));
        c1.LinkEntities(host.Id, ip.Id, EntityRelationshipType.CommunicatedWith, "Outbound session to the attacker IP.", actor, now.AddDays(-5));
        await db.SaveChangesAsync(ct);

        // Case 2 — third-party/vendor breach we are managing.
        var c2 = Case.Open(2026, 2, "Vendor SaaS Breach", "Claims-processing vendor disclosed a data breach",
            Classification.Breach, Severity.High, CaseOrigin.ThirdParty, actor, now.AddDays(-3));
        c2.ThirdParty = new ThirdPartyDetails
        {
            VendorName = "ClaimStream SaaS", VendorContact = "security@claimstream.example", VendorReference = "CS-IR-9931"
        };
        c2.Summary = "Vendor notified us of unauthorized access to a claims dataset that may include our policyholders.";
        c2.DataTypesInvolved = "Policyholder PII; claims history";
        c2.ChangePhase(CasePhase.Triage, "Awaiting vendor scope confirmation", actor, now.AddDays(-3));
        db.Cases.Add(c2);
        await db.SaveChangesAsync(ct);

        // Case 3 — internal adverse event, low severity, still open.
        var c3 = Case.Open(2026, 3, "Anomalous VPN Logins", "Impossible-travel VPN logins for one account",
            Classification.AdverseEvent, Severity.Low, CaseOrigin.InternalDetection, actor, now.AddDays(-1));
        c3.DetectionCaseId = "SIEM-40190";
        c3.Summary = "Single account showed impossible-travel; likely benign VPN egress change, under review.";
        db.Cases.Add(c3);
        await db.SaveChangesAsync(ct);
    }
}
