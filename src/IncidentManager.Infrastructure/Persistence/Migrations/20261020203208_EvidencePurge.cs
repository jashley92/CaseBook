using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class EvidencePurge : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "PurgedAtUtc",
                table: "Evidence",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PurgedBy",
                table: "Evidence",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PurgedReason",
                table: "Evidence",
                type: "TEXT",
                maxLength: 2000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PurgedAtUtc",
                table: "Evidence");

            migrationBuilder.DropColumn(
                name: "PurgedBy",
                table: "Evidence");

            migrationBuilder.DropColumn(
                name: "PurgedReason",
                table: "Evidence");
        }
    }
}
