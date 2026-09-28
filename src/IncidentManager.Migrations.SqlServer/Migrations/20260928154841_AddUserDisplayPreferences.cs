using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AddUserDisplayPreferences : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "UserDisplayPreferences",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    DarkTheme = table.Column<bool>(type: "bit", nullable: false),
                    NavCollapsed = table.Column<bool>(type: "bit", nullable: false),
                    LocalTime = table.Column<bool>(type: "bit", nullable: false),
                    TwelveHourClock = table.Column<bool>(type: "bit", nullable: false),
                    CompactRows = table.Column<bool>(type: "bit", nullable: false),
                    UpdatedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserDisplayPreferences", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_UserDisplayPreferences_UserId",
                table: "UserDisplayPreferences",
                column: "UserId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UserDisplayPreferences");
        }
    }
}
