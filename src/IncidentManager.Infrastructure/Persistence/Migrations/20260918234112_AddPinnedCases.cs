using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPinnedCases : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PinnedCases",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    PinnedAtUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PinnedCases", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PinnedCases_UserId",
                table: "PinnedCases",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_PinnedCases_UserId_CaseId",
                table: "PinnedCases",
                columns: new[] { "UserId", "CaseId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PinnedCases");
        }
    }
}
