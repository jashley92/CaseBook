using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPendingImports : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PendingImports",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SubmittedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    SubmittedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    Origin = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Summary = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    RawJson = table.Column<string>(type: "TEXT", nullable: false),
                    TargetCaseId = table.Column<Guid>(type: "TEXT", nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    DecidedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    DecidedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    DecisionNote = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    ResolvedCaseId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ResolvedCaseNumber = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PendingImports", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PendingImports_Status_SubmittedAtUtc",
                table: "PendingImports",
                columns: new[] { "Status", "SubmittedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PendingImports");
        }
    }
}
