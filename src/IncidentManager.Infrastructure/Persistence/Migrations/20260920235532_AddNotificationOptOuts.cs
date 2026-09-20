using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddNotificationOptOuts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "SuppressAssignment",
                table: "UserNotificationPreferences",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "SuppressDueSoon",
                table: "UserNotificationPreferences",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "SuppressOverdue",
                table: "UserNotificationPreferences",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SuppressAssignment",
                table: "UserNotificationPreferences");

            migrationBuilder.DropColumn(
                name: "SuppressDueSoon",
                table: "UserNotificationPreferences");

            migrationBuilder.DropColumn(
                name: "SuppressOverdue",
                table: "UserNotificationPreferences");
        }
    }
}
