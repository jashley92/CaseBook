using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class NoteMentionsDropDiscussion : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CaseComments");

            migrationBuilder.AddColumn<string>(
                name: "MentionsCsv",
                table: "AnalystNotes",
                type: "TEXT",
                maxLength: 2000,
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MentionsCsv",
                table: "AnalystNotes");

            migrationBuilder.CreateTable(
                name: "CaseComments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Body = table.Column<string>(type: "TEXT", maxLength: 8000, nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    MentionsCsv = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true),
                    ParentId = table.Column<Guid>(type: "TEXT", nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseComments", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CaseComments_CaseId",
                table: "CaseComments",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_CaseComments_ParentId",
                table: "CaseComments",
                column: "ParentId");
        }
    }
}
