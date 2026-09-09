using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IncidentManager.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AdGroupRoleMappings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    AdGroup = table.Column<string>(type: "TEXT", maxLength: 400, nullable: false),
                    RoleName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    UpdatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AdGroupRoleMappings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AppSettings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Key = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Value = table.Column<string>(type: "TEXT", maxLength: 8000, nullable: true),
                    UpdatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppSettings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditLog",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Sequence = table.Column<long>(type: "INTEGER", nullable: false),
                    AtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    Actor = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Action = table.Column<int>(type: "INTEGER", nullable: false),
                    EntityType = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    EntityId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    CaseNumber = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Summary = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    BeforeJson = table.Column<string>(type: "TEXT", nullable: true),
                    AfterJson = table.Column<string>(type: "TEXT", nullable: true),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    PrevHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    EntryHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLog", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CaseAccessEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ActorUserId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CaseNumber = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    AccessType = table.Column<int>(type: "INTEGER", nullable: false),
                    TargetId = table.Column<Guid>(type: "TEXT", nullable: true),
                    TargetLabel = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    WasRestricted = table.Column<bool>(type: "INTEGER", nullable: false),
                    FirstSeenUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastSeenUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    Count = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseAccessEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CaseLinks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RelatedCaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Type = table.Column<int>(type: "INTEGER", nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseLinks", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Cases",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Year = table.Column<int>(type: "INTEGER", nullable: false),
                    Sequence = table.Column<int>(type: "INTEGER", nullable: false),
                    DescriptiveName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    CaseNumber = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    HasCustomNumber = table.Column<bool>(type: "INTEGER", nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    Classification = table.Column<int>(type: "INTEGER", nullable: true),
                    Phase = table.Column<int>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    Origin = table.Column<int>(type: "INTEGER", nullable: false),
                    Summary = table.Column<string>(type: "TEXT", maxLength: 8000, nullable: true),
                    ImpactedAssets = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    DataTypesInvolved = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    AffectedIndividualsCount = table.Column<int>(type: "INTEGER", nullable: true),
                    AffectedStates = table.Column<string>(type: "TEXT", nullable: true),
                    DetectionCaseId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    ThirdParty_VendorName = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                    ThirdParty_VendorContact = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                    ThirdParty_VendorReference = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Legal_IsReferred = table.Column<bool>(type: "INTEGER", nullable: false),
                    Legal_ReferredAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    Legal_ReferredBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Legal_ReferredToContact = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                    Legal_RelevanceNote = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    IncidentCommander = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    IsRestricted = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsArchived = table.Column<bool>(type: "INTEGER", nullable: false),
                    LegalHold = table.Column<bool>(type: "INTEGER", nullable: false),
                    ReportProfileId = table.Column<Guid>(type: "TEXT", nullable: true),
                    OccurredAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    DetectedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ReportedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ContainedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ResolvedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ClosedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Cases", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CaseTemplates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    SortOrder = table.Column<int>(type: "INTEGER", nullable: false),
                    DefaultClassification = table.Column<int>(type: "INTEGER", nullable: true),
                    DefaultSeverity = table.Column<int>(type: "INTEGER", nullable: true),
                    DefaultDataTypes = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    SummaryBoilerplate = table.Column<string>(type: "TEXT", maxLength: 8000, nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseTemplates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DataElements",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Key = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Label = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    SortOrder = table.Column<int>(type: "INTEGER", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsSystem = table.Column<bool>(type: "INTEGER", nullable: false),
                    NotificationJurisdictions = table.Column<string>(type: "TEXT", maxLength: 400, nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DataElements", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "IntegritySeals",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SealedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    UpToSequence = table.Column<long>(type: "INTEGER", nullable: false),
                    ChainHeadHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Signature = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    Algorithm = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    KeyId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    SealedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IntegritySeals", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ReportProfiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    SortOrder = table.Column<int>(type: "INTEGER", nullable: false),
                    SectionLayout = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ReportProfiles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Roles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 400, nullable: true),
                    IsSystem = table.Column<bool>(type: "INTEGER", nullable: false),
                    PermissionsCsv = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    UpdatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    UpdatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Roles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "StageGates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Trigger = table.Column<int>(type: "INTEGER", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    CommentaryMinLength = table.Column<int>(type: "INTEGER", nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StageGates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Sid = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    UserPrincipalName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Email = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                    LastSeenUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    RolesCsv = table.Column<string>(type: "TEXT", maxLength: 400, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ActionItems",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 400, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    Owner = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    DueAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    CompletedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ActionItems", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ActionItems_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AnalystNotes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Body = table.Column<string>(type: "TEXT", maxLength: 16000, nullable: false),
                    Version = table.Column<int>(type: "INTEGER", nullable: false),
                    SupersedesNoteId = table.Column<Guid>(type: "TEXT", nullable: true),
                    IsCurrent = table.Column<bool>(type: "INTEGER", nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AnalystNotes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AnalystNotes_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CaseAssignments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    UserDisplayName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Role = table.Column<int>(type: "INTEGER", nullable: false),
                    AssignedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    AssignedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseAssignments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CaseAssignments_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CaseDataElements",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ElementKey = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseDataElements", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CaseDataElements_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CaseEntities",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Type = table.Column<int>(type: "INTEGER", nullable: false),
                    Value = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    Label = table.Column<string>(type: "TEXT", maxLength: 400, nullable: true),
                    Disposition = table.Column<int>(type: "INTEGER", nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    Source = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseEntities", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CaseEntities_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CaseTechniques",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    TechniqueId = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 400, nullable: false),
                    Tactic = table.Column<int>(type: "INTEGER", nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseTechniques", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CaseTechniques_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClassificationChanges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    From = table.Column<int>(type: "INTEGER", nullable: true),
                    To = table.Column<int>(type: "INTEGER", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    ChangedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ChangedAtUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClassificationChanges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ClassificationChanges_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "EntityLayouts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    EntityId = table.Column<Guid>(type: "TEXT", nullable: false),
                    X = table.Column<double>(type: "REAL", nullable: false),
                    Y = table.Column<double>(type: "REAL", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EntityLayouts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EntityLayouts_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "EntityRelationships",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    SourceEntityId = table.Column<Guid>(type: "TEXT", nullable: false),
                    TargetEntityId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Type = table.Column<int>(type: "INTEGER", nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EntityRelationships", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EntityRelationships_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Evidence",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    OriginalFileName = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    ContentType = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    SizeBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    Sha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    StoragePath = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Evidence", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Evidence_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "GatePassages",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Trigger = table.Column<int>(type: "INTEGER", nullable: false),
                    PassedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    PassedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    WasOverridden = table.Column<bool>(type: "INTEGER", nullable: false),
                    OverrideJustification = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    Commentary = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    Detail = table.Column<string>(type: "TEXT", maxLength: 8000, nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GatePassages", x => x.Id);
                    table.ForeignKey(
                        name: "FK_GatePassages_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Reports",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Version = table.Column<int>(type: "INTEGER", nullable: false),
                    Format = table.Column<int>(type: "INTEGER", nullable: false),
                    FileName = table.Column<string>(type: "TEXT", maxLength: 400, nullable: false),
                    StoragePath = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    ContentSha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    IsFinal = table.Column<bool>(type: "INTEGER", nullable: false),
                    ApprovedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    ApprovedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Reports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Reports_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SeverityChanges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    From = table.Column<int>(type: "INTEGER", nullable: true),
                    To = table.Column<int>(type: "INTEGER", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    ChangedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ChangedAtUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SeverityChanges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SeverityChanges_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "StatusChanges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    From = table.Column<int>(type: "INTEGER", nullable: true),
                    To = table.Column<int>(type: "INTEGER", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    ChangedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ChangedAtUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StatusChanges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_StatusChanges_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CaseTemplateSteps",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    TemplateId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Order = table.Column<int>(type: "INTEGER", nullable: false),
                    Title = table.Column<string>(type: "TEXT", maxLength: 400, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    OwnerHint = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    DueOffsetHours = table.Column<int>(type: "INTEGER", nullable: true),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaseTemplateSteps", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CaseTemplateSteps_CaseTemplates_TemplateId",
                        column: x => x.TemplateId,
                        principalTable: "CaseTemplates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "StageGateRequirements",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    GateId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Order = table.Column<int>(type: "INTEGER", nullable: false),
                    Kind = table.Column<int>(type: "INTEGER", nullable: false),
                    CheckKey = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    CheckParam = table.Column<int>(type: "INTEGER", nullable: true),
                    Label = table.Column<string>(type: "TEXT", maxLength: 400, nullable: false),
                    IsBlocking = table.Column<bool>(type: "INTEGER", nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StageGateRequirements", x => x.Id);
                    table.ForeignKey(
                        name: "FK_StageGateRequirements_StageGates_GateId",
                        column: x => x.GateId,
                        principalTable: "StageGates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TimelineEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CaseId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Kind = table.Column<int>(type: "INTEGER", nullable: false),
                    OccurredAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    Type = table.Column<int>(type: "INTEGER", nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 16000, nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    TechniqueId = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    ActorEntityId = table.Column<Guid>(type: "TEXT", nullable: true),
                    TargetEntityId = table.Column<Guid>(type: "TEXT", nullable: true),
                    EvidenceId = table.Column<Guid>(type: "TEXT", nullable: true),
                    Version = table.Column<int>(type: "INTEGER", nullable: false),
                    SupersedesEntryId = table.Column<Guid>(type: "TEXT", nullable: true),
                    IsCurrent = table.Column<bool>(type: "INTEGER", nullable: false),
                    RowHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    CreatedAtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ModifiedAtUtc = table.Column<long>(type: "INTEGER", nullable: true),
                    ModifiedBy = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TimelineEntries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TimelineEntries_CaseEntities_ActorEntityId",
                        column: x => x.ActorEntityId,
                        principalTable: "CaseEntities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_TimelineEntries_CaseEntities_TargetEntityId",
                        column: x => x.TargetEntityId,
                        principalTable: "CaseEntities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_TimelineEntries_Cases_CaseId",
                        column: x => x.CaseId,
                        principalTable: "Cases",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ChainOfCustodyEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    EvidenceId = table.Column<Guid>(type: "TEXT", nullable: false),
                    AtUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    Actor = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Action = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Details = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ChainOfCustodyEvents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ChainOfCustodyEvents_Evidence_EvidenceId",
                        column: x => x.EvidenceId,
                        principalTable: "Evidence",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "EventStepTactics",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    TimelineEntryId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Tactic = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EventStepTactics", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EventStepTactics_TimelineEntries_TimelineEntryId",
                        column: x => x.TimelineEntryId,
                        principalTable: "TimelineEntries",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ActionItems_CaseId_Status",
                table: "ActionItems",
                columns: new[] { "CaseId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_AdGroupRoleMappings_AdGroup_RoleName",
                table: "AdGroupRoleMappings",
                columns: new[] { "AdGroup", "RoleName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AdGroupRoleMappings_RoleName",
                table: "AdGroupRoleMappings",
                column: "RoleName");

            migrationBuilder.CreateIndex(
                name: "IX_AnalystNotes_CaseId_IsCurrent",
                table: "AnalystNotes",
                columns: new[] { "CaseId", "IsCurrent" });

            migrationBuilder.CreateIndex(
                name: "IX_AppSettings_Key",
                table: "AppSettings",
                column: "Key",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuditLog_AtUtc",
                table: "AuditLog",
                column: "AtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLog_CaseNumber",
                table: "AuditLog",
                column: "CaseNumber");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLog_Sequence",
                table: "AuditLog",
                column: "Sequence",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CaseAccessEvents_ActorUserId_CaseId_AccessType_LastSeenUtc",
                table: "CaseAccessEvents",
                columns: new[] { "ActorUserId", "CaseId", "AccessType", "LastSeenUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CaseAccessEvents_CaseId",
                table: "CaseAccessEvents",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_CaseAccessEvents_LastSeenUtc",
                table: "CaseAccessEvents",
                column: "LastSeenUtc");

            migrationBuilder.CreateIndex(
                name: "IX_CaseAssignments_CaseId_UserId",
                table: "CaseAssignments",
                columns: new[] { "CaseId", "UserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CaseAssignments_UserId",
                table: "CaseAssignments",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_CaseDataElements_CaseId_ElementKey",
                table: "CaseDataElements",
                columns: new[] { "CaseId", "ElementKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CaseEntities_CaseId",
                table: "CaseEntities",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_CaseEntities_CaseId_Type_Value",
                table: "CaseEntities",
                columns: new[] { "CaseId", "Type", "Value" });

            migrationBuilder.CreateIndex(
                name: "IX_CaseLinks_CaseId",
                table: "CaseLinks",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_CaseLinks_CaseId_RelatedCaseId_Type",
                table: "CaseLinks",
                columns: new[] { "CaseId", "RelatedCaseId", "Type" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CaseLinks_RelatedCaseId",
                table: "CaseLinks",
                column: "RelatedCaseId");

            migrationBuilder.CreateIndex(
                name: "IX_Cases_CaseNumber",
                table: "Cases",
                column: "CaseNumber",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Cases_Classification",
                table: "Cases",
                column: "Classification");

            migrationBuilder.CreateIndex(
                name: "IX_Cases_IrpSequence",
                table: "Cases",
                columns: new[] { "Year", "Sequence" },
                unique: true,
                filter: "Classification IS NOT NULL AND HasCustomNumber = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Cases_IsArchived",
                table: "Cases",
                column: "IsArchived");

            migrationBuilder.CreateIndex(
                name: "IX_Cases_Phase",
                table: "Cases",
                column: "Phase");

            migrationBuilder.CreateIndex(
                name: "IX_CaseTechniques_CaseId",
                table: "CaseTechniques",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_CaseTechniques_CaseId_TechniqueId",
                table: "CaseTechniques",
                columns: new[] { "CaseId", "TechniqueId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CaseTemplates_Name",
                table: "CaseTemplates",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CaseTemplateSteps_TemplateId",
                table: "CaseTemplateSteps",
                column: "TemplateId");

            migrationBuilder.CreateIndex(
                name: "IX_ChainOfCustodyEvents_EvidenceId",
                table: "ChainOfCustodyEvents",
                column: "EvidenceId");

            migrationBuilder.CreateIndex(
                name: "IX_ClassificationChanges_CaseId",
                table: "ClassificationChanges",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_DataElements_Key",
                table: "DataElements",
                column: "Key",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EntityLayouts_CaseId",
                table: "EntityLayouts",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_EntityLayouts_EntityId",
                table: "EntityLayouts",
                column: "EntityId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EntityRelationships_CaseId",
                table: "EntityRelationships",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_EntityRelationships_SourceEntityId",
                table: "EntityRelationships",
                column: "SourceEntityId");

            migrationBuilder.CreateIndex(
                name: "IX_EntityRelationships_TargetEntityId",
                table: "EntityRelationships",
                column: "TargetEntityId");

            migrationBuilder.CreateIndex(
                name: "IX_EventStepTactics_TimelineEntryId",
                table: "EventStepTactics",
                column: "TimelineEntryId");

            migrationBuilder.CreateIndex(
                name: "IX_Evidence_CaseId",
                table: "Evidence",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_Evidence_Sha256",
                table: "Evidence",
                column: "Sha256");

            migrationBuilder.CreateIndex(
                name: "IX_GatePassages_CaseId",
                table: "GatePassages",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_IntegritySeals_SealedAtUtc",
                table: "IntegritySeals",
                column: "SealedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ReportProfiles_Name",
                table: "ReportProfiles",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Reports_CaseId",
                table: "Reports",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_Roles_Name",
                table: "Roles",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SeverityChanges_CaseId",
                table: "SeverityChanges",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_StageGateRequirements_GateId",
                table: "StageGateRequirements",
                column: "GateId");

            migrationBuilder.CreateIndex(
                name: "IX_StageGates_Trigger_IsActive",
                table: "StageGates",
                columns: new[] { "Trigger", "IsActive" });

            migrationBuilder.CreateIndex(
                name: "IX_StatusChanges_CaseId",
                table: "StatusChanges",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_TimelineEntries_ActorEntityId",
                table: "TimelineEntries",
                column: "ActorEntityId");

            migrationBuilder.CreateIndex(
                name: "IX_TimelineEntries_CaseId",
                table: "TimelineEntries",
                column: "CaseId");

            migrationBuilder.CreateIndex(
                name: "IX_TimelineEntries_CaseId_Kind_IsCurrent",
                table: "TimelineEntries",
                columns: new[] { "CaseId", "Kind", "IsCurrent" });

            migrationBuilder.CreateIndex(
                name: "IX_TimelineEntries_OccurredAtUtc",
                table: "TimelineEntries",
                column: "OccurredAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_TimelineEntries_TargetEntityId",
                table: "TimelineEntries",
                column: "TargetEntityId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Sid",
                table: "Users",
                column: "Sid",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ActionItems");

            migrationBuilder.DropTable(
                name: "AdGroupRoleMappings");

            migrationBuilder.DropTable(
                name: "AnalystNotes");

            migrationBuilder.DropTable(
                name: "AppSettings");

            migrationBuilder.DropTable(
                name: "AuditLog");

            migrationBuilder.DropTable(
                name: "CaseAccessEvents");

            migrationBuilder.DropTable(
                name: "CaseAssignments");

            migrationBuilder.DropTable(
                name: "CaseDataElements");

            migrationBuilder.DropTable(
                name: "CaseLinks");

            migrationBuilder.DropTable(
                name: "CaseTechniques");

            migrationBuilder.DropTable(
                name: "CaseTemplateSteps");

            migrationBuilder.DropTable(
                name: "ChainOfCustodyEvents");

            migrationBuilder.DropTable(
                name: "ClassificationChanges");

            migrationBuilder.DropTable(
                name: "DataElements");

            migrationBuilder.DropTable(
                name: "EntityLayouts");

            migrationBuilder.DropTable(
                name: "EntityRelationships");

            migrationBuilder.DropTable(
                name: "EventStepTactics");

            migrationBuilder.DropTable(
                name: "GatePassages");

            migrationBuilder.DropTable(
                name: "IntegritySeals");

            migrationBuilder.DropTable(
                name: "ReportProfiles");

            migrationBuilder.DropTable(
                name: "Reports");

            migrationBuilder.DropTable(
                name: "Roles");

            migrationBuilder.DropTable(
                name: "SeverityChanges");

            migrationBuilder.DropTable(
                name: "StageGateRequirements");

            migrationBuilder.DropTable(
                name: "StatusChanges");

            migrationBuilder.DropTable(
                name: "Users");

            migrationBuilder.DropTable(
                name: "CaseTemplates");

            migrationBuilder.DropTable(
                name: "Evidence");

            migrationBuilder.DropTable(
                name: "TimelineEntries");

            migrationBuilder.DropTable(
                name: "StageGates");

            migrationBuilder.DropTable(
                name: "CaseEntities");

            migrationBuilder.DropTable(
                name: "Cases");
        }
    }
}
