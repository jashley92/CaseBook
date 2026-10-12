using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class NotificationMarks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "NotificationMarks",
                columns: table => new
                {
                    Key = table.Column<string>(type: "TEXT", maxLength: 450, nullable: false),
                    SentAtUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NotificationMarks", x => x.Key);
                });

            migrationBuilder.CreateIndex(
                name: "IX_NotificationMarks_SentAtUtc",
                table: "NotificationMarks",
                column: "SentAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "NotificationMarks");
        }
    }
}
