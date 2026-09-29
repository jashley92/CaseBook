using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AddDecisionEntries : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "DecidedBy",
                table: "TimelineEntries",
                type: "nvarchar(300)",
                maxLength: 300,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OptionsConsidered",
                table: "TimelineEntries",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Rationale",
                table: "TimelineEntries",
                type: "nvarchar(4000)",
                maxLength: 4000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DecidedBy",
                table: "TimelineEntries");

            migrationBuilder.DropColumn(
                name: "OptionsConsidered",
                table: "TimelineEntries");

            migrationBuilder.DropColumn(
                name: "Rationale",
                table: "TimelineEntries");
        }
    }
}
