using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class NoticeDetails : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "EvidenceId",
                table: "JurisdictionNotices",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Method",
                table: "JurisdictionNotices",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "NotifiedBy",
                table: "JurisdictionNotices",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Reference",
                table: "JurisdictionNotices",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EvidenceId",
                table: "JurisdictionNotices");

            migrationBuilder.DropColumn(
                name: "Method",
                table: "JurisdictionNotices");

            migrationBuilder.DropColumn(
                name: "NotifiedBy",
                table: "JurisdictionNotices");

            migrationBuilder.DropColumn(
                name: "Reference",
                table: "JurisdictionNotices");
        }
    }
}
