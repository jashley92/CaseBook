using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class CaseEditVersion : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "EditVersion",
                table: "Cases",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            // BUG-113: a race before this release could leave two current briefs on a case. Keep the latest current; the
            // others become earlier versions. IsCurrent isn't in a brief's row hash, so the record check is unaffected.
            migrationBuilder.Sql(
                "UPDATE CaseBriefs SET IsCurrent = 0 WHERE IsCurrent = 1 AND EXISTS (SELECT 1 FROM CaseBriefs o " +
                "WHERE o.CaseId = CaseBriefs.CaseId AND o.IsCurrent = 1 AND (o.Version > CaseBriefs.Version " +
                "OR (o.Version = CaseBriefs.Version AND o.Id > CaseBriefs.Id)))");

            migrationBuilder.CreateIndex(
                name: "IX_CaseBriefs_OneCurrent",
                table: "CaseBriefs",
                columns: new[] { "CaseId", "IsCurrent" },
                unique: true,
                filter: "IsCurrent = 1");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_CaseBriefs_OneCurrent",
                table: "CaseBriefs");

            migrationBuilder.DropColumn(
                name: "EditVersion",
                table: "Cases");
        }
    }
}
