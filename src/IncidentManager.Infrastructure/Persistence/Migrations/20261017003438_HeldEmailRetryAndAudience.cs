using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class HeldEmailRetryAndAudience : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "CaseId",
                table: "HeldEmails",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "NextAttemptAtUtc",
                table: "HeldEmails",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RecipientUserIds",
                table: "HeldEmails",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CaseId",
                table: "HeldEmails");

            migrationBuilder.DropColumn(
                name: "NextAttemptAtUtc",
                table: "HeldEmails");

            migrationBuilder.DropColumn(
                name: "RecipientUserIds",
                table: "HeldEmails");
        }
    }
}
