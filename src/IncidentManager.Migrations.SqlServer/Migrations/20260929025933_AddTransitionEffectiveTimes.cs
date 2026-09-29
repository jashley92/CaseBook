using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AddTransitionEffectiveTimes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "EffectiveAtUtc",
                table: "StatusChanges",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "EffectiveAtUtc",
                table: "SeverityChanges",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "EffectiveAtUtc",
                table: "ClassificationChanges",
                type: "datetimeoffset",
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
