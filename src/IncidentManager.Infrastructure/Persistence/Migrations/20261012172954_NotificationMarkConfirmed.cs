using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class NotificationMarkConfirmed : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "ConfirmedAtUtc",
                table: "NotificationMarks",
                type: "INTEGER",
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
