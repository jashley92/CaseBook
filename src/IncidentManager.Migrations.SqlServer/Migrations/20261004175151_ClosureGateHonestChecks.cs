using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
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
UPDATE q
SET q.[Kind] = 0, q.[CheckKey] = N'LessonsCaptured', q.[CheckParam] = NULL,
    q.[Label] = N'Post-incident review recorded (Incidents & Breaches)', q.[RowHash] = NULL
FROM [StageGateRequirements] q
JOIN [StageGates] g ON g.[Id] = q.[GateId]
WHERE g.[Trigger] = 3 AND q.[Kind] = 1 AND q.[Label] = N'Post-incident review complete'
  AND NOT EXISTS (SELECT 1 FROM [StageGateRequirements] r WHERE r.[GateId] = q.[GateId] AND r.[CheckKey] = N'LessonsCaptured');");

            migrationBuilder.Sql(@"
INSERT INTO [StageGateRequirements] ([Id], [GateId], [Order], [Kind], [CheckKey], [CheckParam], [Label], [IsBlocking], [RowHash])
SELECT NEWID(), g.[Id],
       COALESCE((SELECT MAX(r.[Order]) FROM [StageGateRequirements] r WHERE r.[GateId] = g.[Id]), 0) + 1,
       0, N'EntitiesAssessed', NULL, N'Every entity / IOC has a verdict (none left Unknown)', CAST(0 AS bit), NULL
FROM [StageGates] g
WHERE g.[Trigger] = 3
  AND NOT EXISTS (SELECT 1 FROM [StageGateRequirements] r WHERE r.[GateId] = g.[Id] AND r.[CheckKey] = N'EntitiesAssessed');");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Data only; deliberately not reversed (see Up).
        }
    }
}
