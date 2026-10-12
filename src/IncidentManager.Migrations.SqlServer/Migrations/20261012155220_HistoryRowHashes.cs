using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class HistoryRowHashes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RowHash",
                table: "StatusChanges",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RowHash",
                table: "SeverityChanges",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RowHash",
                table: "MaterialityChanges",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RowHash",
                table: "EvidenceCitations",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RowHash",
                table: "EntityVerdictChanges",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RowHash",
                table: "ClassificationChanges",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RowHash",
                table: "CaseAssignments",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RowHash",
                table: "AssignmentChanges",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RowHash",
                table: "StatusChanges");

            migrationBuilder.DropColumn(
                name: "RowHash",
                table: "SeverityChanges");

            migrationBuilder.DropColumn(
                name: "RowHash",
                table: "MaterialityChanges");

            migrationBuilder.DropColumn(
                name: "RowHash",
                table: "EvidenceCitations");

            migrationBuilder.DropColumn(
                name: "RowHash",
                table: "EntityVerdictChanges");

            migrationBuilder.DropColumn(
                name: "RowHash",
                table: "ClassificationChanges");

            migrationBuilder.DropColumn(
                name: "RowHash",
                table: "CaseAssignments");

            migrationBuilder.DropColumn(
                name: "RowHash",
                table: "AssignmentChanges");
        }
    }
}
