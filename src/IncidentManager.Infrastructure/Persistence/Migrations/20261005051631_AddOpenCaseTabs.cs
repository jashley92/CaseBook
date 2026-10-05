using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddOpenCaseTabs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "OpenCaseTabs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    OpenedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastSeenAtUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OpenCaseTabs", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_OpenCaseTabs_UserId",
                table: "OpenCaseTabs",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_OpenCaseTabs_UserId_CaseId",
                table: "OpenCaseTabs",
                columns: new[] { "UserId", "CaseId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "OpenCaseTabs");
        }
    }
}
