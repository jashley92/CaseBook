using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
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
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RetractedAtUtc",
                table: "TimelineEntries",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RetractedBy",
                table: "TimelineEntries",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "EffectiveAtUtc",
                table: "EntityVerdictChanges",
                type: "datetimeoffset",
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
