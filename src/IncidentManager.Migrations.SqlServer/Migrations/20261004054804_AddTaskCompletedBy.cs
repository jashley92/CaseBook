using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AddTaskCompletedBy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CompletedBy",
                table: "ActionItems",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CompletedBy",
                table: "ActionItems");
        }
    }
}
