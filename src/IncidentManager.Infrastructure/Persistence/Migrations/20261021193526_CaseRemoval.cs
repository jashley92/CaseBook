using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class CaseRemoval : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "PurgedAtUtc",
                table: "Cases",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "RemovedAtUtc",
                table: "Cases",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RemovedBy",
                table: "Cases",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RemovedNumber",
                table: "Cases",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RemovedReason",
                table: "Cases",
                type: "TEXT",
                maxLength: 1000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PurgedAtUtc",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "RemovedAtUtc",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "RemovedBy",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "RemovedNumber",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "RemovedReason",
                table: "Cases");
        }
    }
}
