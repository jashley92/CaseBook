using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ApiTokenRowHash : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RowHash",
                table: "ApiTokens",
                type: "TEXT",
                maxLength: 70,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RowHash",
                table: "ApiTokens");
        }
    }
}
