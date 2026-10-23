using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class StoredFileEncryptedFlag : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "StoredEncrypted",
                table: "Reports",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "StoredEncrypted",
                table: "Evidence",
                type: "bit",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "StoredEncrypted",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "StoredEncrypted",
                table: "Evidence");
        }
    }
}
