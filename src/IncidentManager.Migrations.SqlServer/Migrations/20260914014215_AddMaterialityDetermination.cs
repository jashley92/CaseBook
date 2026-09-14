using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AddMaterialityDetermination : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "Materiality_DecidedOnUtc",
                table: "Cases",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Materiality_DecisionMaker",
                table: "Cases",
                type: "nvarchar(300)",
                maxLength: 300,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Materiality_Rationale",
                table: "Cases",
                type: "nvarchar(4000)",
                maxLength: 4000,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "Materiality_RecordedAtUtc",
                table: "Cases",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Materiality_RecordedBy",
                table: "Cases",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Materiality_Status",
                table: "Cases",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "MaterialityChanges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CaseId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    From = table.Column<int>(type: "int", nullable: false),
                    To = table.Column<int>(type: "int", nullable: false),
                    DecisionMaker = table.Column<string>(type: "nvarchar(300)", maxLength: 300, nullable: true),
                    DecidedOnUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    Rationale = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: true),
                    ChangedBy = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    ChangedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
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
