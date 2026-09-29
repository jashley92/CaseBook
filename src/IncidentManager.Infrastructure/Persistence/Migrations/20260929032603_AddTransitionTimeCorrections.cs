using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddTransitionTimeCorrections : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "TransitionTimeCorrections",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Kind = table.Column<int>(type: "INTEGER", nullable: false),
                    ChangeId = table.Column<Guid>(type: "TEXT", nullable: false),
                    FromEffectiveUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    ToEffectiveUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TransitionTimeCorrections", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TransitionTimeCorrections_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TransitionTimeCorrections_CaseId",
                table: "TransitionTimeCorrections",
                column: "CaseId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TransitionTimeCorrections");
        }
    }
}
