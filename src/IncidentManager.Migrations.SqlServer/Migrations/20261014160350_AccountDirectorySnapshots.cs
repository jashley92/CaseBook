using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AccountDirectorySnapshots : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AccountDirectorySnapshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CaseId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EntityId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    LookedUp = table.Column<string>(type: "nvarchar(400)", maxLength: 400, nullable: false),
                    Trigger = table.Column<int>(type: "int", nullable: false),
                    Found = table.Column<bool>(type: "bit", nullable: false),
                    SamAccountName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    UserPrincipalName = table.Column<string>(type: "nvarchar(400)", maxLength: 400, nullable: true),
                    DisplayName = table.Column<string>(type: "nvarchar(400)", maxLength: 400, nullable: true),
                    Title = table.Column<string>(type: "nvarchar(400)", maxLength: 400, nullable: true),
                    Department = table.Column<string>(type: "nvarchar(400)", maxLength: 400, nullable: true),
                    Manager = table.Column<string>(type: "nvarchar(400)", maxLength: 400, nullable: true),
                    Email = table.Column<string>(type: "nvarchar(400)", maxLength: 400, nullable: true),
                    DistinguishedName = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                    Enabled = table.Column<bool>(type: "bit", nullable: true),
                    LockedOut = table.Column<bool>(type: "bit", nullable: true),
                    AccountExpiresUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    LastLogonUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    PasswordLastSetUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    WhenCreatedUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    RowHash = table.Column<string>(type: "nvarchar(70)", maxLength: 70, nullable: true),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    CreatedBy = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    ModifiedBy = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccountDirectorySnapshots", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AccountDirectorySnapshots_CaseId_EntityId",
                table: "AccountDirectorySnapshots",
                columns: new[] { "CaseId", "EntityId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AccountDirectorySnapshots");
        }
    }
}
