using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddTransitionEffectiveTimes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "EffectiveAtUtc",
                table: "StatusChanges",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "EffectiveAtUtc",
                table: "SeverityChanges",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "EffectiveAtUtc",
                table: "ClassificationChanges",
                type: "INTEGER",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EffectiveAtUtc",
                table: "StatusChanges");

            migrationBuilder.DropColumn(
                name: "EffectiveAtUtc",
                table: "SeverityChanges");

            migrationBuilder.DropColumn(
                name: "EffectiveAtUtc",
                table: "ClassificationChanges");
        }
    }
}
