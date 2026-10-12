using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class NotificationMarkConfirmed : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ConfirmedAtUtc",
                table: "NotificationMarks",
                type: "datetimeoffset",
                nullable: true);

            // BUG-147: marks written before this release were recorded after their send, so they're confirmed.
            migrationBuilder.Sql("UPDATE NotificationMarks SET ConfirmedAtUtc = SentAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ConfirmedAtUtc",
                table: "NotificationMarks");
        }
    }
}
