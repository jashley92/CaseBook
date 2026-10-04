using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddCaseOutcomes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "OutcomeKey",
                table: "StatusChanges",
                type: "TEXT",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OutcomeKey",
                table: "Cases",
                type: "TEXT",
                maxLength: 64,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "CaseOutcomes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Key = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Label = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    SortOrder = table.Column<int>(type: "INTEGER", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsSystem = table.Column<bool>(type: "INTEGER", nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseOutcomes", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Cases_OutcomeKey",
                table: "Cases",
                column: "OutcomeKey");

            migrationBuilder.CreateIndex(
                name: "IX_CaseOutcomes_Key",
                table: "CaseOutcomes",
                column: "Key",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CaseOutcomes");

            migrationBuilder.DropIndex(
                name: "IX_Cases_OutcomeKey",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "OutcomeKey",
                table: "StatusChanges");

            migrationBuilder.DropColumn(
                name: "OutcomeKey",
                table: "Cases");
        }
    }
}
