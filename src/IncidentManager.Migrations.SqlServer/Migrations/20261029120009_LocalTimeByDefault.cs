using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class LocalTimeByDefault : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "LocalTimeNoticePending",
                table: "UserDisplayPreferences",
                type: "bit",
                nullable: false,
                defaultValue: false);

            // Local time became the default: everyone on UTC moves to local time, and is told so once at their next sign-in.
            migrationBuilder.Sql(
                "UPDATE UserDisplayPreferences SET LocalTime = 1, LocalTimeNoticePending = 1 WHERE LocalTime = 0");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LocalTimeNoticePending",
                table: "UserDisplayPreferences");
        }
    }
}
