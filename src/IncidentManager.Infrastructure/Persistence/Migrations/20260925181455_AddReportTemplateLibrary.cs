using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddReportTemplateLibrary : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ReportTemplates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    FileName = table.Column<string>(type: "TEXT", maxLength: 260, nullable: false),
                    Sha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    SizeBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ReportTemplates", x => x.Id);
                });

            migrationBuilder.AddColumn<Guid>(
                name: "TemplateId",
                table: "ReportProfiles",
                type: "TEXT",
                nullable: true);

            // PROD-47: move each profile's uploaded template into the library. The template keeps the profile's id,
            // so its file in the template folder (named by id) is found without moving anything; the profile then
            // points at it as its default. Size isn't known from the row, so it's recorded as 0 until replaced.
            migrationBuilder.Sql(@"
INSERT INTO ""ReportTemplates"" (""Id"", ""Name"", ""FileName"", ""Sha256"", ""SizeBytes"", ""IsActive"", ""RowHash"",
                                ""CreatedAtUtc"", ""CreatedBy"", ""ModifiedAtUtc"", ""ModifiedBy"")
SELECT ""Id"",
       CASE WHEN lower(substr(""TemplateFileName"", -5)) = '.docx'
            THEN substr(""TemplateFileName"", 1, length(""TemplateFileName"") - 5) ELSE ""TemplateFileName"" END,
       ""TemplateFileName"", COALESCE(""TemplateSha256"", ''), 0, 1, NULL,
       COALESCE(""ModifiedAtUtc"", ""CreatedAtUtc""), COALESCE(""ModifiedBy"", ""CreatedBy""), NULL, NULL
FROM ""ReportProfiles"" WHERE ""TemplateFileName"" IS NOT NULL;");
            migrationBuilder.Sql(@"UPDATE ""ReportProfiles"" SET ""TemplateId"" = ""Id"" WHERE ""TemplateFileName"" IS NOT NULL;");

            migrationBuilder.DropColumn(
                name: "TemplateFileName",
                table: "ReportProfiles");

            migrationBuilder.DropColumn(
                name: "TemplateSha256",
                table: "ReportProfiles");

            migrationBuilder.AddColumn<string>(
                name: "TemplateName",
                table: "Reports",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TemplateSha256",
                table: "Reports",
                type: "TEXT",
                maxLength: 64,
                nullable: true);


            migrationBuilder.CreateIndex(
                name: "IX_ReportProfiles_TemplateId",
                table: "ReportProfiles",
                column: "TemplateId");

            migrationBuilder.AddForeignKey(
                name: "FK_ReportProfiles_ReportTemplates_TemplateId",
                table: "ReportProfiles",
                column: "TemplateId",
                principalTable: "ReportTemplates",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ReportProfiles_ReportTemplates_TemplateId",
                table: "ReportProfiles");

            migrationBuilder.DropTable(
                name: "ReportTemplates");

            migrationBuilder.DropIndex(
                name: "IX_ReportProfiles_TemplateId",
                table: "ReportProfiles");

            migrationBuilder.DropColumn(
                name: "TemplateName",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "TemplateSha256",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "TemplateId",
                table: "ReportProfiles");

            migrationBuilder.AddColumn<string>(
                name: "TemplateFileName",
                table: "ReportProfiles",
                type: "TEXT",
                maxLength: 260,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TemplateSha256",
                table: "ReportProfiles",
                type: "TEXT",
                maxLength: 64,
                nullable: true);
        }
    }
}
