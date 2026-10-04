using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ClosureGateHonestChecks : Migration
    {
        /// <summary>
        /// HR-12 (data only), on every existing close-case gate: the shipped "Post-incident review complete" attestation
        /// (unchanged wording, so an admin's own attestation is left alone) becomes the LessonsCaptured machine check,
        /// keeping its place and blocking setting, unless the gate already has that check; and the advisory
        /// EntitiesAssessed check ("none left Unknown") is added after the gate's others, unless it's already there.
        /// A fresh install has no gates yet at this point (the default gates, which already carry both, are seeded
        /// after migrations). Row hashes are left NULL and set on the gate's next save, as in
        /// ClosureGateNotificationsRecorded. Not reversed on Down: an admin may have kept or edited the checks since.
        /// </summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
UPDATE ""StageGateRequirements""
SET ""Kind"" = 0, ""CheckKey"" = 'LessonsCaptured', ""CheckParam"" = NULL,
    ""Label"" = 'Post-incident review recorded (Incidents & Breaches)', ""RowHash"" = NULL
WHERE ""Kind"" = 1 AND ""Label"" = 'Post-incident review complete'
  AND ""GateId"" IN (SELECT g.""Id"" FROM ""StageGates"" g WHERE g.""Trigger"" = 3)
  AND NOT EXISTS (SELECT 1 FROM ""StageGateRequirements"" r
                  WHERE r.""GateId"" = ""StageGateRequirements"".""GateId"" AND r.""CheckKey"" = 'LessonsCaptured');");

            migrationBuilder.Sql(@"
INSERT INTO ""StageGateRequirements"" (""Id"", ""GateId"", ""Order"", ""Kind"", ""CheckKey"", ""CheckParam"", ""Label"", ""IsBlocking"", ""RowHash"")
SELECT upper(hex(randomblob(4))) || '-' || upper(hex(randomblob(2))) || '-4' || substr(upper(hex(randomblob(2))), 2) || '-' ||
       substr('89AB', 1 + (abs(random()) % 4), 1) || substr(upper(hex(randomblob(2))), 2) || '-' || upper(hex(randomblob(6))),
       g.""Id"",
       COALESCE((SELECT MAX(r.""Order"") FROM ""StageGateRequirements"" r WHERE r.""GateId"" = g.""Id""), 0) + 1,
       0, 'EntitiesAssessed', NULL, 'Every entity / IOC has a verdict (none left Unknown)', 0, NULL
FROM ""StageGates"" g
WHERE g.""Trigger"" = 3
  AND NOT EXISTS (SELECT 1 FROM ""StageGateRequirements"" r WHERE r.""GateId"" = g.""Id"" AND r.""CheckKey"" = 'EntitiesAssessed');");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Data only; deliberately not reversed (see Up).
        }
    }
}
