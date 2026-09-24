using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AddLegalHoldReleaseRequest : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "LegalHoldReleaseReason",
                table: "Cases",
                type: "nvarchar(1000)",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LegalHoldReleaseRequestedAtUtc",
                table: "Cases",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LegalHoldReleaseRequestedBy",
                table: "Cases",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LegalHoldReleaseReason",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "LegalHoldReleaseRequestedAtUtc",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "LegalHoldReleaseRequestedBy",
                table: "Cases");
        }
    }
}
