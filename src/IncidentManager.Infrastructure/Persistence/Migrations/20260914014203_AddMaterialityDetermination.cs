using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddMaterialityDetermination : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "Materiality_DecidedOnUtc",
                table: "Cases",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Materiality_DecisionMaker",
                table: "Cases",
                type: "TEXT",
                maxLength: 300,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Materiality_Rationale",
                table: "Cases",
                type: "TEXT",
                maxLength: 4000,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "Materiality_RecordedAtUtc",
                table: "Cases",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Materiality_RecordedBy",
                table: "Cases",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Materiality_Status",
                table: "Cases",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "MaterialityChanges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    From = table.Column<int>(type: "INTEGER", nullable: false),
                    To = table.Column<int>(type: "INTEGER", nullable: false),
                    DecisionMaker = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                    DecidedOnUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    Rationale = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    ChangedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ChangedAtUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MaterialityChanges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MaterialityChanges_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_MaterialityChanges_CaseId",
                table: "MaterialityChanges",
                column: "CaseId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MaterialityChanges");

            migrationBuilder.DropColumn(
                name: "Materiality_DecidedOnUtc",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "Materiality_DecisionMaker",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "Materiality_Rationale",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "Materiality_RecordedAtUtc",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "Materiality_RecordedBy",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "Materiality_Status",
                table: "Cases");
        }
    }
}
