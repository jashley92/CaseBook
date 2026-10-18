using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class EvidenceWithdrawal : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "WithdrawnAtUtc",
                table: "Evidence",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "WithdrawnBy",
                table: "Evidence",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "WithdrawnReason",
                table: "Evidence",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "WithdrawnAtUtc",
                table: "Evidence");

            migrationBuilder.DropColumn(
                name: "WithdrawnBy",
                table: "Evidence");

            migrationBuilder.DropColumn(
                name: "WithdrawnReason",
                table: "Evidence");
        }
    }
}
