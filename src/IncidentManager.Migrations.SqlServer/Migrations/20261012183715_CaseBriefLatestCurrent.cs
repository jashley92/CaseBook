using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class CaseBriefLatestCurrent : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // BUG-185: CaseEditVersion kept one current brief per case, breaking a tie on Version by Id, so of two briefs a
            // race saved from the same one it kept either. Where the current brief is the latest version and a sibling of
            // that version was saved later, the later one becomes current, as its save also set the case summary.
            // IsCurrent isn't in a brief's row hash, so the record check is unaffected.
            migrationBuilder.Sql(
                "UPDATE CaseBriefs SET IsCurrent = 0 WHERE IsCurrent = 1 " +
                "AND NOT EXISTS (SELECT 1 FROM CaseBriefs h WHERE h.CaseId = CaseBriefs.CaseId AND h.Version > CaseBriefs.Version) " +
                "AND EXISTS (SELECT 1 FROM CaseBriefs o WHERE o.CaseId = CaseBriefs.CaseId AND o.IsCurrent = 0 " +
                "AND o.Version = CaseBriefs.Version AND (o.CreatedAtUtc > CaseBriefs.CreatedAtUtc " +
                "OR (o.CreatedAtUtc = CaseBriefs.CreatedAtUtc AND o.Id > CaseBriefs.Id)))");
            // Then each case with briefs but none current (the ones just changed) gets its latest: highest version, then
            // the last saved.
            migrationBuilder.Sql(
                "UPDATE CaseBriefs SET IsCurrent = 1 " +
                "WHERE NOT EXISTS (SELECT 1 FROM CaseBriefs c WHERE c.CaseId = CaseBriefs.CaseId AND c.IsCurrent = 1) " +
                "AND NOT EXISTS (SELECT 1 FROM CaseBriefs o WHERE o.CaseId = CaseBriefs.CaseId AND (o.Version > CaseBriefs.Version " +
                "OR (o.Version = CaseBriefs.Version AND (o.CreatedAtUtc > CaseBriefs.CreatedAtUtc " +
                "OR (o.CreatedAtUtc = CaseBriefs.CreatedAtUtc AND o.Id > CaseBriefs.Id)))))");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Nothing to undo: which brief is current isn't a schema change.
        }
    }
}
