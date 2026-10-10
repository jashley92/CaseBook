using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
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
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "OccurredUntilUtc",
                table: "TimelineEntries",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "StepOrder",
                table: "TimelineEntries",
                type: "int",
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
