using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class SmtpSignIn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SmtpSignIns",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false),
                    Mode = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    Username = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    ProtectedPassword = table.Column<string>(type: "TEXT", nullable: true),
                    PasswordSetAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    PasswordSetBy = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    UpdatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedBy = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SmtpSignIns", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SmtpSignIns");
        }
    }
}
