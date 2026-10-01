using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class ClosureGateNotificationsRecorded : Migration
    {
        /// <summary>
        /// INV-43 (data only): add the "Required regulatory notifications recorded" check to every existing
        /// close-case gate that doesn't have it, as a blocking requirement after its others — so closing a case
        /// with a running, unrecorded notification clock needs an override justification, as on new installs.
        /// A fresh install has no gates yet at this point (the default gates, which already carry the check, are
        /// seeded after migrations). The row hash is left NULL and set on the gate's next save, as with the
        /// report-template data step. Not reversed on Down: an admin may have kept or edited the check since.
        /// </summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
INSERT INTO [StageGateRequirements] ([Id], [GateId], [Order], [Kind], [CheckKey], [CheckParam], [Label], [IsBlocking], [RowHash])
SELECT NEWID(), g.[Id],
       COALESCE((SELECT MAX(r.[Order]) FROM [StageGateRequirements] r WHERE r.[GateId] = g.[Id]), 0) + 1,
       0, N'NotificationsRecorded', NULL, N'Required regulatory notifications recorded', CAST(1 AS bit), NULL
FROM [StageGates] g
WHERE g.[Trigger] = 3
  AND NOT EXISTS (SELECT 1 FROM [StageGateRequirements] r WHERE r.[GateId] = g.[Id] AND r.[CheckKey] = N'NotificationsRecorded');");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Data only; deliberately not reversed (see Up).
        }
    }
}
