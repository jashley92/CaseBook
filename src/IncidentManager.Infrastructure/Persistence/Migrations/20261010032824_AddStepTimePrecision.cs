using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddStepTimePrecision : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "OccurredPrecision",
                table: "TimelineEntries",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "OccurredUntilUtc",
                table: "TimelineEntries",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "StepOrder",
                table: "TimelineEntries",
                type: "INTEGER",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "OccurredPrecision",
                table: "TimelineEntries");

            migrationBuilder.DropColumn(
                name: "OccurredUntilUtc",
                table: "TimelineEntries");

            migrationBuilder.DropColumn(
                name: "StepOrder",
                table: "TimelineEntries");
        }
    }
}
