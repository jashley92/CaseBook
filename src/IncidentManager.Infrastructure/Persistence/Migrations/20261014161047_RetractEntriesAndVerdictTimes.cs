using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class RetractEntriesAndVerdictTimes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RetractReason",
                table: "TimelineEntries",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "RetractedAtUtc",
                table: "TimelineEntries",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RetractedBy",
                table: "TimelineEntries",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "EffectiveAtUtc",
                table: "EntityVerdictChanges",
                type: "INTEGER",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RetractReason",
                table: "TimelineEntries");

            migrationBuilder.DropColumn(
                name: "RetractedAtUtc",
                table: "TimelineEntries");

            migrationBuilder.DropColumn(
                name: "RetractedBy",
                table: "TimelineEntries");

            migrationBuilder.DropColumn(
                name: "EffectiveAtUtc",
                table: "EntityVerdictChanges");
        }
    }
}
