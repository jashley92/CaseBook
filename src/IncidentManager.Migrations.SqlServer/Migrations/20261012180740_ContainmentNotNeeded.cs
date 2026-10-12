using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class ContainmentNotNeeded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ContainmentNotNeededReason",
                table: "Cases",
                type: "nvarchar(1000)",
                maxLength: 1000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ContainmentNotNeededReason",
                table: "Cases");
        }
    }
}
