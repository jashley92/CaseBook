using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class EvidenceWithdrawal : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "WithdrawnAtUtc",
                table: "Evidence",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "WithdrawnBy",
                table: "Evidence",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "WithdrawnReason",
                table: "Evidence",
                type: "TEXT",
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
