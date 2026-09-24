using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPostIncidentReview : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "Kind",
                table: "Reports",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "ImprovementActions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 400, nullable: false),
                    RelatedArea = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Details = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    Owner = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    TargetDateUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    ClosedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    OutcomeNote = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ImprovementActions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ImprovementActions_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "PostIncidentReviews",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    WhatHappened = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    ContributingFactors = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    WhatWorkedWell = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    OpportunitiesToImprove = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    NoActionsIdentified = table.Column<bool>(type: "INTEGER", nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PostIncidentReviews", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PostIncidentReviews_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ImprovementActions_CaseId",
                table: "ImprovementActions",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_ImprovementActions_Status_TargetDateUtc",
                table: "ImprovementActions",
                columns: new[] { "Status", "TargetDateUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_PostIncidentReviews_CaseId",
                table: "PostIncidentReviews",
                column: "CaseId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ImprovementActions");

            migrationBuilder.DropTable(
                name: "PostIncidentReviews");

            migrationBuilder.DropColumn(
                name: "Kind",
                table: "Reports");
        }
    }
}
