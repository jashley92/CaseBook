using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <summary>
    /// CAP-22: nothing on SQLite, which has no full-text indexes here and always searches by substring. The SQL Server
    /// migration of the same name creates them where the server has Full-Text Search; this keeps the two sets in step.
    /// </summary>
    public partial class FullTextSearch : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {

        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {

        }
    }
}
