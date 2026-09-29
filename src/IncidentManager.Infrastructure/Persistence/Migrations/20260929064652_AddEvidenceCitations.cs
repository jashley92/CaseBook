using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddEvidenceCitations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "EvidenceCitations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    TimelineEntryId = table.Column<Guid>(type: "TEXT", nullable: false),
                    EvidenceId = table.Column<Guid>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EvidenceCitations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EvidenceCitations_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_EvidenceCitations_CaseId",
                table: "EvidenceCitations",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_EvidenceCitations_EvidenceId",
                table: "EvidenceCitations",
                column: "EvidenceId");

            migrationBuilder.CreateIndex(
                name: "IX_EvidenceCitations_TimelineEntryId_EvidenceId",
                table: "EvidenceCitations",
                columns: new[] { "TimelineEntryId", "EvidenceId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EvidenceCitations");
        }
    }
}
