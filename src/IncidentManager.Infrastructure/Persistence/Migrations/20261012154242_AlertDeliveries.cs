using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AlertDeliveries : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AlertDeliveries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Kind = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CaseNumber = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Recipients = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: false),
                    Subject = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    HtmlBody = table.Column<string>(type: "TEXT", nullable: false),
                    TextBody = table.Column<string>(type: "TEXT", nullable: false),
                    FirstFailedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    Retries = table.Column<int>(type: "INTEGER", nullable: false),
                    NextAttemptAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    DeliveredAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    GaveUpAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    DismissedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    DismissedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AlertDeliveries", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AlertDeliveries_CaseId",
                table: "AlertDeliveries",
                column: "CaseId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AlertDeliveries");
        }
    }
}
