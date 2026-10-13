using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class PendingImportHash : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RawJsonSha256",
                table: "PendingImports",
                type: "nvarchar(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_PendingImports_SubmittedBy_RawJsonSha256",
                table: "PendingImports",
                columns: new[] { "SubmittedBy", "RawJsonSha256" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PendingImports_SubmittedBy_RawJsonSha256",
                table: "PendingImports");

            migrationBuilder.DropColumn(
                name: "RawJsonSha256",
                table: "PendingImports");
        }
    }
}
