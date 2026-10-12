using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class CaseEntityIndexFitsSqlServer : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_CaseEntities_CaseId_Type_Value",
                table: "CaseEntities");

            migrationBuilder.CreateIndex(
                name: "IX_CaseEntities_CaseId_Type",
                table: "CaseEntities",
                columns: new[] { "CaseId", "Type" })
                .Annotation("SqlServer:Include", new[] { "Value" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_CaseEntities_CaseId_Type",
                table: "CaseEntities");

            migrationBuilder.CreateIndex(
                name: "IX_CaseEntities_CaseId_Type_Value",
                table: "CaseEntities",
                columns: new[] { "CaseId", "Type", "Value" });
        }
    }
}
