using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AddTeams : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "TeamId",
                table: "SavedViews",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "TeamId",
                table: "Cases",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "Teams",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Key = table.Column<string>(type: "nvarchar(40)", maxLength: 40, nullable: false),
                    Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    DetectionSourceLabel = table.Column<string>(type: "nvarchar(60)", maxLength: 60, nullable: true),
                    DetectionLinkTemplate = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: true),
                    RowHash = table.Column<string>(type: "nvarchar(70)", maxLength: 70, nullable: true),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    CreatedBy = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    ModifiedBy = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Teams", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TeamMembers",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TeamId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    AddedAtUtc = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    AddedBy = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    RowHash = table.Column<string>(type: "nvarchar(70)", maxLength: 70, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TeamMembers", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TeamMembers_Teams_TeamId",
                        column: x => x.TeamId,
                        principalTable: "Teams",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SavedViews_TeamId",
                table: "SavedViews",
                column: "TeamId");

            migrationBuilder.CreateIndex(
                name: "IX_Cases_TeamId",
                table: "Cases",
                column: "TeamId");

            migrationBuilder.CreateIndex(
                name: "IX_TeamMembers_TeamId_UserId",
                table: "TeamMembers",
                columns: new[] { "TeamId", "UserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TeamMembers_UserId",
                table: "TeamMembers",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_Teams_Key",
                table: "Teams",
                column: "Key",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Teams_Name",
                table: "Teams",
                column: "Name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TeamMembers");

            migrationBuilder.DropTable(
                name: "Teams");

            migrationBuilder.DropIndex(
                name: "IX_SavedViews_TeamId",
                table: "SavedViews");

            migrationBuilder.DropIndex(
                name: "IX_Cases_TeamId",
                table: "Cases");

            migrationBuilder.DropColumn(
                name: "TeamId",
                table: "SavedViews");

            migrationBuilder.DropColumn(
                name: "TeamId",
                table: "Cases");
        }
    }
}
