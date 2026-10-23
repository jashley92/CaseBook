IF OBJECT_ID(N'[__EFMigrationsHistory]') IS NULL
BEGIN
    CREATE TABLE [__EFMigrationsHistory] (
        [MigrationId] nvarchar(150) NOT NULL,
        [ProductVersion] nvarchar(32) NOT NULL,
        CONSTRAINT [PK___EFMigrationsHistory] PRIMARY KEY ([MigrationId])
    );
END;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [AdGroupRoleMappings] (
        [Id] uniqueidentifier NOT NULL,
        [AdGroup] nvarchar(400) NOT NULL,
        [RoleName] nvarchar(100) NOT NULL,
        [UpdatedAtUtc] datetimeoffset NOT NULL,
        [UpdatedBy] nvarchar(200) NOT NULL,
        [RowHash] nvarchar(64) NULL,
        CONSTRAINT [PK_AdGroupRoleMappings] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [AppSettings] (
        [Id] uniqueidentifier NOT NULL,
        [Key] nvarchar(200) NOT NULL,
        [Value] nvarchar(max) NULL,
        [UpdatedAtUtc] datetimeoffset NOT NULL,
        [UpdatedBy] nvarchar(200) NOT NULL,
        [RowHash] nvarchar(64) NULL,
        CONSTRAINT [PK_AppSettings] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [AuditLog] (
        [Id] uniqueidentifier NOT NULL,
        [Sequence] bigint NOT NULL,
        [AtUtc] datetimeoffset NOT NULL,
        [Actor] nvarchar(200) NOT NULL,
        [Action] int NOT NULL,
        [EntityType] nvarchar(100) NOT NULL,
        [EntityId] nvarchar(100) NULL,
        [CaseNumber] nvarchar(200) NULL,
        [Summary] nvarchar(2000) NULL,
        [BeforeJson] nvarchar(max) NULL,
        [AfterJson] nvarchar(max) NULL,
        [Reason] nvarchar(2000) NULL,
        [PrevHash] nvarchar(64) NOT NULL,
        [EntryHash] nvarchar(64) NOT NULL,
        CONSTRAINT [PK_AuditLog] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [CaseAccessEvents] (
        [Id] uniqueidentifier NOT NULL,
        [ActorUserId] nvarchar(200) NOT NULL,
        [CaseId] uniqueidentifier NULL,
        [CaseNumber] nvarchar(200) NULL,
        [AccessType] int NOT NULL,
        [TargetId] uniqueidentifier NULL,
        [TargetLabel] nvarchar(500) NULL,
        [WasRestricted] bit NOT NULL,
        [FirstSeenUtc] datetimeoffset NOT NULL,
        [LastSeenUtc] datetimeoffset NOT NULL,
        [Count] int NOT NULL,
        CONSTRAINT [PK_CaseAccessEvents] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [CaseLinks] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [RelatedCaseId] uniqueidentifier NOT NULL,
        [Type] int NOT NULL,
        [Description] nvarchar(2000) NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_CaseLinks] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [Cases] (
        [Id] uniqueidentifier NOT NULL,
        [Year] int NOT NULL,
        [Sequence] int NOT NULL,
        [DescriptiveName] nvarchar(200) NOT NULL,
        [CaseNumber] nvarchar(200) NOT NULL,
        [HasCustomNumber] bit NOT NULL,
        [Title] nvarchar(300) NOT NULL,
        [Classification] int NULL,
        [Phase] int NOT NULL,
        [Severity] int NOT NULL,
        [Origin] int NOT NULL,
        [Summary] nvarchar(max) NULL,
        [ImpactedAssets] nvarchar(4000) NULL,
        [DataTypesInvolved] nvarchar(4000) NULL,
        [AffectedIndividualsCount] int NULL,
        [AffectedStates] nvarchar(max) NULL,
        [DetectionCaseId] nvarchar(100) NULL,
        [ThirdParty_VendorName] nvarchar(300) NULL,
        [ThirdParty_VendorContact] nvarchar(300) NULL,
        [ThirdParty_VendorReference] nvarchar(200) NULL,
        [Legal_IsReferred] bit NOT NULL,
        [Legal_ReferredAtUtc] datetimeoffset NULL,
        [Legal_ReferredBy] nvarchar(200) NULL,
        [Legal_ReferredToContact] nvarchar(300) NULL,
        [Legal_RelevanceNote] nvarchar(4000) NULL,
        [IncidentCommander] nvarchar(200) NULL,
        [IsRestricted] bit NOT NULL,
        [IsArchived] bit NOT NULL,
        [LegalHold] bit NOT NULL,
        [ReportProfileId] uniqueidentifier NULL,
        [OccurredAtUtc] datetimeoffset NULL,
        [DetectedAtUtc] datetimeoffset NULL,
        [ReportedAtUtc] datetimeoffset NULL,
        [ContainedAtUtc] datetimeoffset NULL,
        [ResolvedAtUtc] datetimeoffset NULL,
        [ClosedAtUtc] datetimeoffset NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(200) NULL,
        CONSTRAINT [PK_Cases] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [CaseTemplates] (
        [Id] uniqueidentifier NOT NULL,
        [Name] nvarchar(200) NOT NULL,
        [Description] nvarchar(2000) NULL,
        [IsActive] bit NOT NULL,
        [SortOrder] int NOT NULL,
        [DefaultClassification] int NULL,
        [DefaultSeverity] int NULL,
        [DefaultDataTypes] nvarchar(2000) NULL,
        [SummaryBoilerplate] nvarchar(max) NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_CaseTemplates] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [DataElements] (
        [Id] uniqueidentifier NOT NULL,
        [Key] nvarchar(100) NOT NULL,
        [Label] nvarchar(200) NOT NULL,
        [SortOrder] int NOT NULL,
        [IsActive] bit NOT NULL,
        [IsSystem] bit NOT NULL,
        [NotificationJurisdictions] nvarchar(400) NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(200) NULL,
        CONSTRAINT [PK_DataElements] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [IntegritySeals] (
        [Id] uniqueidentifier NOT NULL,
        [SealedAtUtc] datetimeoffset NOT NULL,
        [UpToSequence] bigint NOT NULL,
        [ChainHeadHash] nvarchar(64) NOT NULL,
        [Signature] nvarchar(1024) NOT NULL,
        [Algorithm] nvarchar(50) NOT NULL,
        [KeyId] nvarchar(100) NOT NULL,
        [SealedBy] nvarchar(200) NOT NULL,
        CONSTRAINT [PK_IntegritySeals] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [ReportProfiles] (
        [Id] uniqueidentifier NOT NULL,
        [Name] nvarchar(200) NOT NULL,
        [Description] nvarchar(2000) NULL,
        [IsActive] bit NOT NULL,
        [SortOrder] int NOT NULL,
        [SectionLayout] nvarchar(1000) NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_ReportProfiles] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [Roles] (
        [Id] uniqueidentifier NOT NULL,
        [Name] nvarchar(100) NOT NULL,
        [Description] nvarchar(400) NULL,
        [IsSystem] bit NOT NULL,
        [PermissionsCsv] nvarchar(1000) NOT NULL,
        [UpdatedAtUtc] datetimeoffset NOT NULL,
        [UpdatedBy] nvarchar(200) NOT NULL,
        [RowHash] nvarchar(64) NULL,
        CONSTRAINT [PK_Roles] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [StageGates] (
        [Id] uniqueidentifier NOT NULL,
        [Trigger] int NOT NULL,
        [IsActive] bit NOT NULL,
        [Name] nvarchar(200) NOT NULL,
        [Description] nvarchar(2000) NULL,
        [CommentaryMinLength] int NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_StageGates] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [Users] (
        [Id] uniqueidentifier NOT NULL,
        [Sid] nvarchar(200) NOT NULL,
        [UserPrincipalName] nvarchar(200) NOT NULL,
        [DisplayName] nvarchar(200) NOT NULL,
        [Email] nvarchar(300) NULL,
        [LastSeenUtc] datetimeoffset NOT NULL,
        [RolesCsv] nvarchar(400) NOT NULL,
        CONSTRAINT [PK_Users] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [ActionItems] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Title] nvarchar(400) NOT NULL,
        [Description] nvarchar(4000) NULL,
        [Owner] nvarchar(200) NULL,
        [DueAtUtc] datetimeoffset NULL,
        [Status] int NOT NULL,
        [CompletedAtUtc] datetimeoffset NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_ActionItems] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_ActionItems_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [AnalystNotes] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Body] nvarchar(max) NOT NULL,
        [Version] int NOT NULL,
        [SupersedesNoteId] uniqueidentifier NULL,
        [IsCurrent] bit NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_AnalystNotes] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_AnalystNotes_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [CaseAssignments] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [UserId] nvarchar(200) NOT NULL,
        [UserDisplayName] nvarchar(200) NOT NULL,
        [Role] int NOT NULL,
        [AssignedAtUtc] datetimeoffset NOT NULL,
        [AssignedBy] nvarchar(200) NOT NULL,
        CONSTRAINT [PK_CaseAssignments] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_CaseAssignments_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [CaseDataElements] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [ElementKey] nvarchar(100) NOT NULL,
        CONSTRAINT [PK_CaseDataElements] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_CaseDataElements_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [CaseEntities] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Type] int NOT NULL,
        [Value] nvarchar(2000) NOT NULL,
        [Label] nvarchar(400) NULL,
        [Disposition] int NOT NULL,
        [Description] nvarchar(4000) NULL,
        [Source] nvarchar(200) NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_CaseEntities] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_CaseEntities_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [CaseTechniques] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [TechniqueId] nvarchar(20) NOT NULL,
        [Name] nvarchar(400) NOT NULL,
        [Tactic] int NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_CaseTechniques] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_CaseTechniques_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [ClassificationChanges] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [From] int NULL,
        [To] int NOT NULL,
        [Reason] nvarchar(2000) NOT NULL,
        [ChangedBy] nvarchar(200) NOT NULL,
        [ChangedAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_ClassificationChanges] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_ClassificationChanges_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [EntityLayouts] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [EntityId] uniqueidentifier NOT NULL,
        [X] float NOT NULL,
        [Y] float NOT NULL,
        CONSTRAINT [PK_EntityLayouts] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_EntityLayouts_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [EntityRelationships] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [SourceEntityId] uniqueidentifier NOT NULL,
        [TargetEntityId] uniqueidentifier NOT NULL,
        [Type] int NOT NULL,
        [Description] nvarchar(2000) NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_EntityRelationships] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_EntityRelationships_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [Evidence] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [OriginalFileName] nvarchar(500) NOT NULL,
        [ContentType] nvarchar(200) NOT NULL,
        [SizeBytes] bigint NOT NULL,
        [Sha256] nvarchar(64) NOT NULL,
        [StoragePath] nvarchar(500) NOT NULL,
        [Description] nvarchar(2000) NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_Evidence] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_Evidence_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [GatePassages] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Trigger] int NOT NULL,
        [PassedAtUtc] datetimeoffset NOT NULL,
        [PassedBy] nvarchar(200) NOT NULL,
        [WasOverridden] bit NOT NULL,
        [OverrideJustification] nvarchar(2000) NULL,
        [Commentary] nvarchar(4000) NULL,
        [Detail] nvarchar(max) NOT NULL,
        [RowHash] nvarchar(64) NULL,
        CONSTRAINT [PK_GatePassages] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_GatePassages_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [Reports] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Version] int NOT NULL,
        [Format] int NOT NULL,
        [FileName] nvarchar(400) NOT NULL,
        [StoragePath] nvarchar(500) NOT NULL,
        [ContentSha256] nvarchar(64) NOT NULL,
        [IsFinal] bit NOT NULL,
        [ApprovedBy] nvarchar(200) NULL,
        [ApprovedAtUtc] datetimeoffset NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_Reports] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_Reports_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [SeverityChanges] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [From] int NULL,
        [To] int NOT NULL,
        [Reason] nvarchar(2000) NULL,
        [ChangedBy] nvarchar(200) NOT NULL,
        [ChangedAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_SeverityChanges] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_SeverityChanges_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [StatusChanges] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [From] int NULL,
        [To] int NOT NULL,
        [Reason] nvarchar(2000) NULL,
        [ChangedBy] nvarchar(200) NOT NULL,
        [ChangedAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_StatusChanges] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_StatusChanges_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [CaseTemplateSteps] (
        [Id] uniqueidentifier NOT NULL,
        [TemplateId] uniqueidentifier NOT NULL,
        [Order] int NOT NULL,
        [Title] nvarchar(400) NOT NULL,
        [Description] nvarchar(4000) NULL,
        [OwnerHint] nvarchar(200) NULL,
        [DueOffsetHours] int NULL,
        [RowHash] nvarchar(64) NULL,
        CONSTRAINT [PK_CaseTemplateSteps] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_CaseTemplateSteps_CaseTemplates_TemplateId] FOREIGN KEY ([TemplateId]) REFERENCES [CaseTemplates] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [StageGateRequirements] (
        [Id] uniqueidentifier NOT NULL,
        [GateId] uniqueidentifier NOT NULL,
        [Order] int NOT NULL,
        [Kind] int NOT NULL,
        [CheckKey] nvarchar(100) NULL,
        [CheckParam] int NULL,
        [Label] nvarchar(400) NOT NULL,
        [IsBlocking] bit NOT NULL,
        [RowHash] nvarchar(64) NULL,
        CONSTRAINT [PK_StageGateRequirements] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_StageGateRequirements_StageGates_GateId] FOREIGN KEY ([GateId]) REFERENCES [StageGates] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [TimelineEntries] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Kind] int NOT NULL,
        [OccurredAtUtc] datetimeoffset NOT NULL,
        [Type] int NOT NULL,
        [Description] nvarchar(max) NOT NULL,
        [Source] nvarchar(200) NULL,
        [TechniqueId] nvarchar(20) NULL,
        [ActorEntityId] uniqueidentifier NULL,
        [TargetEntityId] uniqueidentifier NULL,
        [EvidenceId] uniqueidentifier NULL,
        [Version] int NOT NULL,
        [SupersedesEntryId] uniqueidentifier NULL,
        [IsCurrent] bit NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_TimelineEntries] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_TimelineEntries_CaseEntities_ActorEntityId] FOREIGN KEY ([ActorEntityId]) REFERENCES [CaseEntities] ([Id]) ON DELETE NO ACTION,
        CONSTRAINT [FK_TimelineEntries_CaseEntities_TargetEntityId] FOREIGN KEY ([TargetEntityId]) REFERENCES [CaseEntities] ([Id]) ON DELETE NO ACTION,
        CONSTRAINT [FK_TimelineEntries_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [ChainOfCustodyEvents] (
        [Id] uniqueidentifier NOT NULL,
        [EvidenceId] uniqueidentifier NOT NULL,
        [AtUtc] datetimeoffset NOT NULL,
        [Actor] nvarchar(200) NOT NULL,
        [Action] nvarchar(100) NOT NULL,
        [Details] nvarchar(2000) NULL,
        CONSTRAINT [PK_ChainOfCustodyEvents] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_ChainOfCustodyEvents_Evidence_EvidenceId] FOREIGN KEY ([EvidenceId]) REFERENCES [Evidence] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE TABLE [EventStepTactics] (
        [Id] uniqueidentifier NOT NULL,
        [TimelineEntryId] uniqueidentifier NOT NULL,
        [Tactic] int NOT NULL,
        CONSTRAINT [PK_EventStepTactics] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_EventStepTactics_TimelineEntries_TimelineEntryId] FOREIGN KEY ([TimelineEntryId]) REFERENCES [TimelineEntries] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_ActionItems_CaseId_Status] ON [ActionItems] ([CaseId], [Status]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_AdGroupRoleMappings_AdGroup_RoleName] ON [AdGroupRoleMappings] ([AdGroup], [RoleName]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AdGroupRoleMappings_RoleName] ON [AdGroupRoleMappings] ([RoleName]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AnalystNotes_CaseId_IsCurrent] ON [AnalystNotes] ([CaseId], [IsCurrent]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_AppSettings_Key] ON [AppSettings] ([Key]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AuditLog_AtUtc] ON [AuditLog] ([AtUtc]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AuditLog_CaseNumber] ON [AuditLog] ([CaseNumber]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_AuditLog_Sequence] ON [AuditLog] ([Sequence]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseAccessEvents_ActorUserId_CaseId_AccessType_LastSeenUtc] ON [CaseAccessEvents] ([ActorUserId], [CaseId], [AccessType], [LastSeenUtc]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseAccessEvents_CaseId] ON [CaseAccessEvents] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseAccessEvents_LastSeenUtc] ON [CaseAccessEvents] ([LastSeenUtc]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_CaseAssignments_CaseId_UserId] ON [CaseAssignments] ([CaseId], [UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseAssignments_UserId] ON [CaseAssignments] ([UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_CaseDataElements_CaseId_ElementKey] ON [CaseDataElements] ([CaseId], [ElementKey]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseEntities_CaseId] ON [CaseEntities] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseEntities_CaseId_Type_Value] ON [CaseEntities] ([CaseId], [Type], [Value]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseLinks_CaseId] ON [CaseLinks] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_CaseLinks_CaseId_RelatedCaseId_Type] ON [CaseLinks] ([CaseId], [RelatedCaseId], [Type]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseLinks_RelatedCaseId] ON [CaseLinks] ([RelatedCaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_Cases_CaseNumber] ON [Cases] ([CaseNumber]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Cases_Classification] ON [Cases] ([Classification]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    EXEC(N'CREATE UNIQUE INDEX [IX_Cases_IrpSequence] ON [Cases] ([Year], [Sequence]) WHERE Classification IS NOT NULL AND HasCustomNumber = 0');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Cases_IsArchived] ON [Cases] ([IsArchived]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Cases_Phase] ON [Cases] ([Phase]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseTechniques_CaseId] ON [CaseTechniques] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_CaseTechniques_CaseId_TechniqueId] ON [CaseTechniques] ([CaseId], [TechniqueId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_CaseTemplates_Name] ON [CaseTemplates] ([Name]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseTemplateSteps_TemplateId] ON [CaseTemplateSteps] ([TemplateId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_ChainOfCustodyEvents_EvidenceId] ON [ChainOfCustodyEvents] ([EvidenceId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_ClassificationChanges_CaseId] ON [ClassificationChanges] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_DataElements_Key] ON [DataElements] ([Key]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_EntityLayouts_CaseId] ON [EntityLayouts] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_EntityLayouts_EntityId] ON [EntityLayouts] ([EntityId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_EntityRelationships_CaseId] ON [EntityRelationships] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_EntityRelationships_SourceEntityId] ON [EntityRelationships] ([SourceEntityId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_EntityRelationships_TargetEntityId] ON [EntityRelationships] ([TargetEntityId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_EventStepTactics_TimelineEntryId] ON [EventStepTactics] ([TimelineEntryId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Evidence_CaseId] ON [Evidence] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Evidence_Sha256] ON [Evidence] ([Sha256]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_GatePassages_CaseId] ON [GatePassages] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_IntegritySeals_SealedAtUtc] ON [IntegritySeals] ([SealedAtUtc]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_ReportProfiles_Name] ON [ReportProfiles] ([Name]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Reports_CaseId] ON [Reports] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_Roles_Name] ON [Roles] ([Name]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_SeverityChanges_CaseId] ON [SeverityChanges] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_StageGateRequirements_GateId] ON [StageGateRequirements] ([GateId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_StageGates_Trigger_IsActive] ON [StageGates] ([Trigger], [IsActive]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_StatusChanges_CaseId] ON [StatusChanges] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_TimelineEntries_ActorEntityId] ON [TimelineEntries] ([ActorEntityId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_TimelineEntries_CaseId] ON [TimelineEntries] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_TimelineEntries_CaseId_Kind_IsCurrent] ON [TimelineEntries] ([CaseId], [Kind], [IsCurrent]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_TimelineEntries_OccurredAtUtc] ON [TimelineEntries] ([OccurredAtUtc]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_TimelineEntries_TargetEntityId] ON [TimelineEntries] ([TargetEntityId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_Users_Sid] ON [Users] ([Sid]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260909194827_InitialCreate'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260909194827_InitialCreate'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260913055758_AddSavedViews'
)
BEGIN
    CREATE TABLE [SavedViews] (
        [Id] uniqueidentifier NOT NULL,
        [OwnerUserId] nvarchar(200) NOT NULL,
        [Name] nvarchar(120) NOT NULL,
        [Query] nvarchar(2000) NOT NULL,
        [IsShared] bit NOT NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_SavedViews] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260913055758_AddSavedViews'
)
BEGIN
    CREATE INDEX [IX_SavedViews_IsShared] ON [SavedViews] ([IsShared]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260913055758_AddSavedViews'
)
BEGIN
    CREATE INDEX [IX_SavedViews_OwnerUserId] ON [SavedViews] ([OwnerUserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260913055758_AddSavedViews'
)
BEGIN
    CREATE UNIQUE INDEX [IX_SavedViews_OwnerUserId_Name] ON [SavedViews] ([OwnerUserId], [Name]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260913055758_AddSavedViews'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260913055758_AddSavedViews'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260913130041_AddCaseComments'
)
BEGIN
    CREATE TABLE [CaseComments] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [ParentId] uniqueidentifier NULL,
        [Body] nvarchar(max) NOT NULL,
        [MentionsCsv] nvarchar(2000) NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_CaseComments] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260913130041_AddCaseComments'
)
BEGIN
    CREATE INDEX [IX_CaseComments_CaseId] ON [CaseComments] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260913130041_AddCaseComments'
)
BEGIN
    CREATE INDEX [IX_CaseComments_ParentId] ON [CaseComments] ([ParentId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260913130041_AddCaseComments'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260913130041_AddCaseComments'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914014215_AddMaterialityDetermination'
)
BEGIN
    ALTER TABLE [Cases] ADD [Materiality_DecidedOnUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914014215_AddMaterialityDetermination'
)
BEGIN
    ALTER TABLE [Cases] ADD [Materiality_DecisionMaker] nvarchar(300) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914014215_AddMaterialityDetermination'
)
BEGIN
    ALTER TABLE [Cases] ADD [Materiality_Rationale] nvarchar(4000) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914014215_AddMaterialityDetermination'
)
BEGIN
    ALTER TABLE [Cases] ADD [Materiality_RecordedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914014215_AddMaterialityDetermination'
)
BEGIN
    ALTER TABLE [Cases] ADD [Materiality_RecordedBy] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914014215_AddMaterialityDetermination'
)
BEGIN
    ALTER TABLE [Cases] ADD [Materiality_Status] int NOT NULL DEFAULT 0;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914014215_AddMaterialityDetermination'
)
BEGIN
    CREATE TABLE [MaterialityChanges] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [From] int NOT NULL,
        [To] int NOT NULL,
        [DecisionMaker] nvarchar(300) NULL,
        [DecidedOnUtc] datetimeoffset NULL,
        [Rationale] nvarchar(4000) NULL,
        [ChangedBy] nvarchar(200) NOT NULL,
        [ChangedAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_MaterialityChanges] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_MaterialityChanges_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914014215_AddMaterialityDetermination'
)
BEGIN
    CREATE INDEX [IX_MaterialityChanges_CaseId] ON [MaterialityChanges] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914014215_AddMaterialityDetermination'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260914014215_AddMaterialityDetermination'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914032412_AddNotificationRules'
)
BEGIN
    CREATE TABLE [NotificationRules] (
        [Id] uniqueidentifier NOT NULL,
        [Code] nvarchar(16) NOT NULL,
        [Label] nvarchar(200) NOT NULL,
        [WindowHours] int NOT NULL,
        [IsActive] bit NOT NULL,
        [IsSystem] bit NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(200) NULL,
        CONSTRAINT [PK_NotificationRules] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914032412_AddNotificationRules'
)
BEGIN
    CREATE UNIQUE INDEX [IX_NotificationRules_Code] ON [NotificationRules] ([Code]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260914032412_AddNotificationRules'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260914032412_AddNotificationRules'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260918234125_AddPinnedCases'
)
BEGIN
    CREATE TABLE [PinnedCases] (
        [Id] uniqueidentifier NOT NULL,
        [UserId] nvarchar(200) NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [PinnedAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_PinnedCases] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260918234125_AddPinnedCases'
)
BEGIN
    CREATE INDEX [IX_PinnedCases_UserId] ON [PinnedCases] ([UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260918234125_AddPinnedCases'
)
BEGIN
    CREATE UNIQUE INDEX [IX_PinnedCases_UserId_CaseId] ON [PinnedCases] ([UserId], [CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260918234125_AddPinnedCases'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260918234125_AddPinnedCases'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260919000735_AddDefaultSavedView'
)
BEGIN
    ALTER TABLE [SavedViews] ADD [IsDefault] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260919000735_AddDefaultSavedView'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260919000735_AddDefaultSavedView'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920134054_AddPendingImports'
)
BEGIN
    CREATE TABLE [PendingImports] (
        [Id] uniqueidentifier NOT NULL,
        [SubmittedBy] nvarchar(200) NOT NULL,
        [SubmittedAtUtc] datetimeoffset NOT NULL,
        [Origin] nvarchar(200) NULL,
        [Summary] nvarchar(300) NOT NULL,
        [RawJson] nvarchar(max) NOT NULL,
        [TargetCaseId] uniqueidentifier NULL,
        [Status] int NOT NULL,
        [DecidedBy] nvarchar(200) NULL,
        [DecidedAtUtc] datetimeoffset NULL,
        [DecisionNote] nvarchar(2000) NULL,
        [ResolvedCaseId] uniqueidentifier NULL,
        [ResolvedCaseNumber] nvarchar(200) NULL,
        CONSTRAINT [PK_PendingImports] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920134054_AddPendingImports'
)
BEGIN
    CREATE INDEX [IX_PendingImports_Status_SubmittedAtUtc] ON [PendingImports] ([Status], [SubmittedAtUtc]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920134054_AddPendingImports'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260920134054_AddPendingImports'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920143522_AddApiTokens'
)
BEGIN
    CREATE TABLE [ApiTokens] (
        [Id] uniqueidentifier NOT NULL,
        [Name] nvarchar(100) NOT NULL,
        [Kind] int NOT NULL,
        [OwnerUserId] nvarchar(200) NOT NULL,
        [OwnerDisplayName] nvarchar(200) NOT NULL,
        [RolesCsv] nvarchar(400) NOT NULL,
        [TokenHash] nvarchar(64) NOT NULL,
        [Prefix] nvarchar(20) NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [ExpiresAtUtc] datetimeoffset NOT NULL,
        [RevokedAtUtc] datetimeoffset NULL,
        [RevokedBy] nvarchar(200) NULL,
        [LastUsedAtUtc] datetimeoffset NULL,
        CONSTRAINT [PK_ApiTokens] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920143522_AddApiTokens'
)
BEGIN
    CREATE INDEX [IX_ApiTokens_CreatedBy] ON [ApiTokens] ([CreatedBy]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920143522_AddApiTokens'
)
BEGIN
    CREATE UNIQUE INDEX [IX_ApiTokens_TokenHash] ON [ApiTokens] ([TokenHash]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920143522_AddApiTokens'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260920143522_AddApiTokens'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920233957_AddUserNotificationPreferences'
)
BEGIN
    CREATE TABLE [UserNotificationPreferences] (
        [Id] uniqueidentifier NOT NULL,
        [UserId] nvarchar(200) NOT NULL,
        [DigestCadence] int NOT NULL,
        [UpdatedAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_UserNotificationPreferences] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920233957_AddUserNotificationPreferences'
)
BEGIN
    CREATE UNIQUE INDEX [IX_UserNotificationPreferences_UserId] ON [UserNotificationPreferences] ([UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920233957_AddUserNotificationPreferences'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260920233957_AddUserNotificationPreferences'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920235541_AddNotificationOptOuts'
)
BEGIN
    ALTER TABLE [UserNotificationPreferences] ADD [SuppressAssignment] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920235541_AddNotificationOptOuts'
)
BEGIN
    ALTER TABLE [UserNotificationPreferences] ADD [SuppressDueSoon] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920235541_AddNotificationOptOuts'
)
BEGIN
    ALTER TABLE [UserNotificationPreferences] ADD [SuppressOverdue] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260920235541_AddNotificationOptOuts'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260920235541_AddNotificationOptOuts'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260921054724_AddCaseExerciseFlag'
)
BEGIN
    ALTER TABLE [Cases] ADD [IsExercise] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260921054724_AddCaseExerciseFlag'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260921054724_AddCaseExerciseFlag'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260921223520_AddActionItemComments'
)
BEGIN
    CREATE TABLE [ActionItemComments] (
        [Id] uniqueidentifier NOT NULL,
        [ActionItemId] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Body] nvarchar(max) NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_ActionItemComments] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260921223520_AddActionItemComments'
)
BEGIN
    CREATE INDEX [IX_ActionItemComments_ActionItemId] ON [ActionItemComments] ([ActionItemId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260921223520_AddActionItemComments'
)
BEGIN
    CREATE INDEX [IX_ActionItemComments_CaseId] ON [ActionItemComments] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260921223520_AddActionItemComments'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260921223520_AddActionItemComments'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260921230204_AddAuditEntityLabel'
)
BEGIN
    ALTER TABLE [AuditLog] ADD [EntityLabel] nvarchar(300) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260921230204_AddAuditEntityLabel'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260921230204_AddAuditEntityLabel'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924044617_AddPostIncidentReview'
)
BEGIN
    ALTER TABLE [Reports] ADD [Kind] int NOT NULL DEFAULT 0;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924044617_AddPostIncidentReview'
)
BEGIN
    CREATE TABLE [ImprovementActions] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Title] nvarchar(400) NOT NULL,
        [RelatedArea] nvarchar(200) NULL,
        [Details] nvarchar(4000) NULL,
        [Owner] nvarchar(200) NULL,
        [TargetDateUtc] datetimeoffset NULL,
        [Status] int NOT NULL,
        [ClosedAtUtc] datetimeoffset NULL,
        [OutcomeNote] nvarchar(4000) NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(200) NULL,
        CONSTRAINT [PK_ImprovementActions] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_ImprovementActions_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924044617_AddPostIncidentReview'
)
BEGIN
    CREATE TABLE [PostIncidentReviews] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [WhatHappened] nvarchar(4000) NULL,
        [ContributingFactors] nvarchar(4000) NULL,
        [WhatWorkedWell] nvarchar(4000) NULL,
        [OpportunitiesToImprove] nvarchar(4000) NULL,
        [NoActionsIdentified] bit NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(200) NULL,
        CONSTRAINT [PK_PostIncidentReviews] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_PostIncidentReviews_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924044617_AddPostIncidentReview'
)
BEGIN
    CREATE INDEX [IX_ImprovementActions_CaseId] ON [ImprovementActions] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924044617_AddPostIncidentReview'
)
BEGIN
    CREATE INDEX [IX_ImprovementActions_Status_TargetDateUtc] ON [ImprovementActions] ([Status], [TargetDateUtc]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924044617_AddPostIncidentReview'
)
BEGIN
    CREATE UNIQUE INDEX [IX_PostIncidentReviews_CaseId] ON [PostIncidentReviews] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924044617_AddPostIncidentReview'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260924044617_AddPostIncidentReview'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924112734_AddLegalHoldReleaseRequest'
)
BEGIN
    ALTER TABLE [Cases] ADD [LegalHoldReleaseReason] nvarchar(1000) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924112734_AddLegalHoldReleaseRequest'
)
BEGIN
    ALTER TABLE [Cases] ADD [LegalHoldReleaseRequestedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924112734_AddLegalHoldReleaseRequest'
)
BEGIN
    ALTER TABLE [Cases] ADD [LegalHoldReleaseRequestedBy] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924112734_AddLegalHoldReleaseRequest'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260924112734_AddLegalHoldReleaseRequest'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924153921_AddAgendaFeedLinkIssuedAt'
)
BEGIN
    ALTER TABLE [Users] ADD [FeedLinkIssuedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924153921_AddAgendaFeedLinkIssuedAt'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260924153921_AddAgendaFeedLinkIssuedAt'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924194443_AddTlpMarkings'
)
BEGIN
    ALTER TABLE [Reports] ADD [Tlp] int NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924194443_AddTlpMarkings'
)
BEGIN
    ALTER TABLE [CaseEntities] ADD [Tlp] int NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924194443_AddTlpMarkings'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260924194443_AddTlpMarkings'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924200616_AddReportProfileTemplate'
)
BEGIN
    ALTER TABLE [ReportProfiles] ADD [TemplateFileName] nvarchar(260) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924200616_AddReportProfileTemplate'
)
BEGIN
    ALTER TABLE [ReportProfiles] ADD [TemplateSha256] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260924200616_AddReportProfileTemplate'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260924200616_AddReportProfileTemplate'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260925181541_AddReportTemplateLibrary'
)
BEGIN
    CREATE TABLE [ReportTemplates] (
        [Id] uniqueidentifier NOT NULL,
        [Name] nvarchar(200) NOT NULL,
        [FileName] nvarchar(260) NOT NULL,
        [Sha256] nvarchar(64) NOT NULL,
        [SizeBytes] bigint NOT NULL,
        [IsActive] bit NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_ReportTemplates] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260925181541_AddReportTemplateLibrary'
)
BEGIN
    ALTER TABLE [ReportProfiles] ADD [TemplateId] uniqueidentifier NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260925181541_AddReportTemplateLibrary'
)
BEGIN
    EXEC(N'    INSERT INTO [ReportTemplates] ([Id], [Name], [FileName], [Sha256], [SizeBytes], [IsActive], [RowHash],
                                   [CreatedAtUtc], [CreatedBy], [ModifiedAtUtc], [ModifiedBy])
    SELECT [Id],
           CASE WHEN LOWER(RIGHT([TemplateFileName], 5)) = N''.docx''
                THEN LEFT([TemplateFileName], LEN([TemplateFileName]) - 5) ELSE [TemplateFileName] END,
           [TemplateFileName], COALESCE([TemplateSha256], N''''), 0, 1, NULL,
           COALESCE([ModifiedAtUtc], [CreatedAtUtc]), COALESCE([ModifiedBy], [CreatedBy]), NULL, NULL
    FROM [ReportProfiles] WHERE [TemplateFileName] IS NOT NULL;');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260925181541_AddReportTemplateLibrary'
)
BEGIN
    EXEC(N'    UPDATE [ReportProfiles] SET [TemplateId] = [Id] WHERE [TemplateFileName] IS NOT NULL;');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260925181541_AddReportTemplateLibrary'
)
BEGIN
    DECLARE @var nvarchar(max);
    SELECT @var = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[ReportProfiles]') AND [c].[name] = N'TemplateFileName');
    IF @var IS NOT NULL EXEC(N'ALTER TABLE [ReportProfiles] DROP CONSTRAINT ' + @var + ';');
    ALTER TABLE [ReportProfiles] DROP COLUMN [TemplateFileName];
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260925181541_AddReportTemplateLibrary'
)
BEGIN
    DECLARE @var1 nvarchar(max);
    SELECT @var1 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[ReportProfiles]') AND [c].[name] = N'TemplateSha256');
    IF @var1 IS NOT NULL EXEC(N'ALTER TABLE [ReportProfiles] DROP CONSTRAINT ' + @var1 + ';');
    ALTER TABLE [ReportProfiles] DROP COLUMN [TemplateSha256];
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260925181541_AddReportTemplateLibrary'
)
BEGIN
    ALTER TABLE [Reports] ADD [TemplateName] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260925181541_AddReportTemplateLibrary'
)
BEGIN
    ALTER TABLE [Reports] ADD [TemplateSha256] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260925181541_AddReportTemplateLibrary'
)
BEGIN
    CREATE INDEX [IX_ReportProfiles_TemplateId] ON [ReportProfiles] ([TemplateId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260925181541_AddReportTemplateLibrary'
)
BEGIN
    ALTER TABLE [ReportProfiles] ADD CONSTRAINT [FK_ReportProfiles_ReportTemplates_TemplateId] FOREIGN KEY ([TemplateId]) REFERENCES [ReportTemplates] ([Id]) ON DELETE NO ACTION;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260925181541_AddReportTemplateLibrary'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260925181541_AddReportTemplateLibrary'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260927180902_AddLessonsDefaultTemplate'
)
BEGIN
    ALTER TABLE [ReportTemplates] ADD [IsLessonsDefault] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260927180902_AddLessonsDefaultTemplate'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260927180902_AddLessonsDefaultTemplate'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260928154841_AddUserDisplayPreferences'
)
BEGIN
    CREATE TABLE [UserDisplayPreferences] (
        [Id] uniqueidentifier NOT NULL,
        [UserId] nvarchar(200) NOT NULL,
        [DarkTheme] bit NOT NULL,
        [NavCollapsed] bit NOT NULL,
        [LocalTime] bit NOT NULL,
        [TwelveHourClock] bit NOT NULL,
        [CompactRows] bit NOT NULL,
        [UpdatedAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_UserDisplayPreferences] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260928154841_AddUserDisplayPreferences'
)
BEGIN
    CREATE UNIQUE INDEX [IX_UserDisplayPreferences_UserId] ON [UserDisplayPreferences] ([UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260928154841_AddUserDisplayPreferences'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260928154841_AddUserDisplayPreferences'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929025933_AddTransitionEffectiveTimes'
)
BEGIN
    ALTER TABLE [StatusChanges] ADD [EffectiveAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929025933_AddTransitionEffectiveTimes'
)
BEGIN
    ALTER TABLE [SeverityChanges] ADD [EffectiveAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929025933_AddTransitionEffectiveTimes'
)
BEGIN
    ALTER TABLE [ClassificationChanges] ADD [EffectiveAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929025933_AddTransitionEffectiveTimes'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260929025933_AddTransitionEffectiveTimes'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929032611_AddTransitionTimeCorrections'
)
BEGIN
    CREATE TABLE [TransitionTimeCorrections] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Kind] int NOT NULL,
        [ChangeId] uniqueidentifier NOT NULL,
        [FromEffectiveUtc] datetimeoffset NOT NULL,
        [ToEffectiveUtc] datetimeoffset NOT NULL,
        [Reason] nvarchar(2000) NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_TransitionTimeCorrections] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_TransitionTimeCorrections_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929032611_AddTransitionTimeCorrections'
)
BEGIN
    CREATE INDEX [IX_TransitionTimeCorrections_CaseId] ON [TransitionTimeCorrections] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929032611_AddTransitionTimeCorrections'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260929032611_AddTransitionTimeCorrections'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929033644_AddDecisionEntries'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [DecidedBy] nvarchar(300) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929033644_AddDecisionEntries'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [OptionsConsidered] nvarchar(2000) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929033644_AddDecisionEntries'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [Rationale] nvarchar(4000) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929033644_AddDecisionEntries'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260929033644_AddDecisionEntries'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929035849_AddTimelineEntryTaskLink'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [ActionItemId] uniqueidentifier NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929035849_AddTimelineEntryTaskLink'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260929035849_AddTimelineEntryTaskLink'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929040211_AddTimelineEntryPromotedFrom'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [PromotedFrom] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929040211_AddTimelineEntryPromotedFrom'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260929040211_AddTimelineEntryPromotedFrom'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929042238_AddCaseBriefs'
)
BEGIN
    CREATE TABLE [CaseBriefs] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Version] int NOT NULL,
        [SupersedesBriefId] uniqueidentifier NULL,
        [IsCurrent] bit NOT NULL,
        [Situation] nvarchar(max) NULL,
        [WorkingAssessment] nvarchar(max) NULL,
        [Known] nvarchar(max) NULL,
        [OpenQuestions] nvarchar(max) NULL,
        [NextSteps] nvarchar(max) NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_CaseBriefs] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_CaseBriefs_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929042238_AddCaseBriefs'
)
BEGIN
    CREATE INDEX [IX_CaseBriefs_CaseId] ON [CaseBriefs] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929042238_AddCaseBriefs'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260929042238_AddCaseBriefs'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929064238_AddTaskKind'
)
BEGIN
    ALTER TABLE [ActionItems] ADD [Kind] int NOT NULL DEFAULT 0;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929064238_AddTaskKind'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260929064238_AddTaskKind'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929064658_AddEvidenceCitations'
)
BEGIN
    CREATE TABLE [EvidenceCitations] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [TimelineEntryId] uniqueidentifier NOT NULL,
        [EvidenceId] uniqueidentifier NOT NULL,
        CONSTRAINT [PK_EvidenceCitations] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_EvidenceCitations_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929064658_AddEvidenceCitations'
)
BEGIN
    CREATE INDEX [IX_EvidenceCitations_CaseId] ON [EvidenceCitations] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929064658_AddEvidenceCitations'
)
BEGIN
    CREATE INDEX [IX_EvidenceCitations_EvidenceId] ON [EvidenceCitations] ([EvidenceId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929064658_AddEvidenceCitations'
)
BEGIN
    CREATE UNIQUE INDEX [IX_EvidenceCitations_TimelineEntryId_EvidenceId] ON [EvidenceCitations] ([TimelineEntryId], [EvidenceId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260929064658_AddEvidenceCitations'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260929064658_AddEvidenceCitations'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930020835_RenameBriefSituationToSummary'
)
BEGIN
    EXEC sp_rename N'[CaseBriefs].[Situation]', N'Summary', 'COLUMN';
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930020835_RenameBriefSituationToSummary'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260930020835_RenameBriefSituationToSummary'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930034733_TaskRaisedFromBrief'
)
BEGIN
    ALTER TABLE [ActionItems] ADD [RaisedFromBriefId] uniqueidentifier NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930034733_TaskRaisedFromBrief'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260930034733_TaskRaisedFromBrief'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930035947_AttackChainOpenPreference'
)
BEGIN
    ALTER TABLE [UserDisplayPreferences] ADD [AttackChainOpen] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930035947_AttackChainOpenPreference'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260930035947_AttackChainOpenPreference'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930041809_NoteMentionsDropDiscussion'
)
BEGIN
    DROP TABLE [CaseComments];
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930041809_NoteMentionsDropDiscussion'
)
BEGIN
    ALTER TABLE [AnalystNotes] ADD [MentionsCsv] nvarchar(2000) NOT NULL DEFAULT N'';
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930041809_NoteMentionsDropDiscussion'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260930041809_NoteMentionsDropDiscussion'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930045710_TaskAboutAndStepKind'
)
BEGIN
    ALTER TABLE [CaseTemplateSteps] ADD [Kind] int NOT NULL DEFAULT 0;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930045710_TaskAboutAndStepKind'
)
BEGIN
    ALTER TABLE [ActionItems] ADD [AboutRef] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930045710_TaskAboutAndStepKind'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260930045710_TaskAboutAndStepKind'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930050314_AssignmentChanges'
)
BEGIN
    CREATE TABLE [AssignmentChanges] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [UserId] nvarchar(200) NOT NULL,
        [UserDisplayName] nvarchar(200) NOT NULL,
        [From] int NULL,
        [To] int NULL,
        [ChangedBy] nvarchar(200) NOT NULL,
        [ChangedAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_AssignmentChanges] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_AssignmentChanges_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930050314_AssignmentChanges'
)
BEGIN
    CREATE INDEX [IX_AssignmentChanges_CaseId] ON [AssignmentChanges] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930050314_AssignmentChanges'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260930050314_AssignmentChanges'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930050612_EntityPinned'
)
BEGIN
    ALTER TABLE [CaseEntities] ADD [IsPinned] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260930050612_EntityPinned'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20260930050612_EntityPinned'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261001005319_ClosureGateNotificationsRecorded'
)
BEGIN
    EXEC(N'    INSERT INTO [StageGateRequirements] ([Id], [GateId], [Order], [Kind], [CheckKey], [CheckParam], [Label], [IsBlocking], [RowHash])
    SELECT NEWID(), g.[Id],
           COALESCE((SELECT MAX(r.[Order]) FROM [StageGateRequirements] r WHERE r.[GateId] = g.[Id]), 0) + 1,
           0, N''NotificationsRecorded'', NULL, N''Required regulatory notifications recorded'', CAST(1 AS bit), NULL
    FROM [StageGates] g
    WHERE g.[Trigger] = 3
      AND NOT EXISTS (SELECT 1 FROM [StageGateRequirements] r WHERE r.[GateId] = g.[Id] AND r.[CheckKey] = N''NotificationsRecorded'');');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261001005319_ClosureGateNotificationsRecorded'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261001005319_ClosureGateNotificationsRecorded'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004054804_AddTaskCompletedBy'
)
BEGIN
    ALTER TABLE [ActionItems] ADD [CompletedBy] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004054804_AddTaskCompletedBy'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261004054804_AddTaskCompletedBy'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004060405_AddCaseOutcomes'
)
BEGIN
    ALTER TABLE [StatusChanges] ADD [OutcomeKey] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004060405_AddCaseOutcomes'
)
BEGIN
    ALTER TABLE [Cases] ADD [OutcomeKey] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004060405_AddCaseOutcomes'
)
BEGIN
    CREATE TABLE [CaseOutcomes] (
        [Id] uniqueidentifier NOT NULL,
        [Key] nvarchar(64) NOT NULL,
        [Label] nvarchar(200) NOT NULL,
        [Description] nvarchar(500) NULL,
        [SortOrder] int NOT NULL,
        [IsActive] bit NOT NULL,
        [IsSystem] bit NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(200) NULL,
        CONSTRAINT [PK_CaseOutcomes] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004060405_AddCaseOutcomes'
)
BEGIN
    CREATE INDEX [IX_Cases_OutcomeKey] ON [Cases] ([OutcomeKey]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004060405_AddCaseOutcomes'
)
BEGIN
    CREATE UNIQUE INDEX [IX_CaseOutcomes_Key] ON [CaseOutcomes] ([Key]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004060405_AddCaseOutcomes'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261004060405_AddCaseOutcomes'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004094442_AddEntityVerdictChanges'
)
BEGIN
    CREATE TABLE [EntityVerdictChanges] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [EntityId] uniqueidentifier NOT NULL,
        [EntityLabel] nvarchar(400) NOT NULL,
        [From] int NOT NULL,
        [To] int NOT NULL,
        [Reason] nvarchar(2000) NULL,
        [ChangedBy] nvarchar(200) NOT NULL,
        [ChangedAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_EntityVerdictChanges] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_EntityVerdictChanges_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004094442_AddEntityVerdictChanges'
)
BEGIN
    CREATE INDEX [IX_EntityVerdictChanges_CaseId] ON [EntityVerdictChanges] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004094442_AddEntityVerdictChanges'
)
BEGIN
    CREATE INDEX [IX_EntityVerdictChanges_EntityId] ON [EntityVerdictChanges] ([EntityId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004094442_AddEntityVerdictChanges'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261004094442_AddEntityVerdictChanges'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004175151_ClosureGateHonestChecks'
)
BEGIN
    EXEC(N'    UPDATE q
    SET q.[Kind] = 0, q.[CheckKey] = N''LessonsCaptured'', q.[CheckParam] = NULL,
        q.[Label] = N''Post-incident review recorded (Incidents & Breaches)'', q.[RowHash] = NULL
    FROM [StageGateRequirements] q
    JOIN [StageGates] g ON g.[Id] = q.[GateId]
    WHERE g.[Trigger] = 3 AND q.[Kind] = 1 AND q.[Label] = N''Post-incident review complete''
      AND NOT EXISTS (SELECT 1 FROM [StageGateRequirements] r WHERE r.[GateId] = q.[GateId] AND r.[CheckKey] = N''LessonsCaptured'');');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004175151_ClosureGateHonestChecks'
)
BEGIN
    EXEC(N'    INSERT INTO [StageGateRequirements] ([Id], [GateId], [Order], [Kind], [CheckKey], [CheckParam], [Label], [IsBlocking], [RowHash])
    SELECT NEWID(), g.[Id],
           COALESCE((SELECT MAX(r.[Order]) FROM [StageGateRequirements] r WHERE r.[GateId] = g.[Id]), 0) + 1,
           0, N''EntitiesAssessed'', NULL, N''Every entity / IOC has a verdict (none left Unknown)'', CAST(0 AS bit), NULL
    FROM [StageGates] g
    WHERE g.[Trigger] = 3
      AND NOT EXISTS (SELECT 1 FROM [StageGateRequirements] r WHERE r.[GateId] = g.[Id] AND r.[CheckKey] = N''EntitiesAssessed'');');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004175151_ClosureGateHonestChecks'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261004175151_ClosureGateHonestChecks'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004223836_AddBriefConfirmation'
)
BEGIN
    ALTER TABLE [CaseBriefs] ADD [ConfirmedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004223836_AddBriefConfirmation'
)
BEGIN
    ALTER TABLE [CaseBriefs] ADD [ConfirmedBy] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261004223836_AddBriefConfirmation'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261004223836_AddBriefConfirmation'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261005051639_AddOpenCaseTabs'
)
BEGIN
    CREATE TABLE [OpenCaseTabs] (
        [Id] uniqueidentifier NOT NULL,
        [UserId] nvarchar(200) NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [OpenedAtUtc] datetimeoffset NOT NULL,
        [LastSeenAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_OpenCaseTabs] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261005051639_AddOpenCaseTabs'
)
BEGIN
    CREATE INDEX [IX_OpenCaseTabs_UserId] ON [OpenCaseTabs] ([UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261005051639_AddOpenCaseTabs'
)
BEGIN
    CREATE UNIQUE INDEX [IX_OpenCaseTabs_UserId_CaseId] ON [OpenCaseTabs] ([UserId], [CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261005051639_AddOpenCaseTabs'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261005051639_AddOpenCaseTabs'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261005083920_AddKeymapPreferences'
)
BEGIN
    ALTER TABLE [UserDisplayPreferences] ADD [KeyBindings] nvarchar(2000) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261005083920_AddKeymapPreferences'
)
BEGIN
    ALTER TABLE [UserDisplayPreferences] ADD [SingleKeyShortcutsOff] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261005083920_AddKeymapPreferences'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261005083920_AddKeymapPreferences'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261007040154_AddStepEnvironment'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [Environment] int NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261007040154_AddStepEnvironment'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261007040154_AddStepEnvironment'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261009185500_AddAuditHashKeyId'
)
BEGIN
    ALTER TABLE [AuditLog] ADD [HashKeyId] nvarchar(16) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261009185500_AddAuditHashKeyId'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261009185500_AddAuditHashKeyId'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261010032839_AddStepTimePrecision'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [OccurredPrecision] int NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261010032839_AddStepTimePrecision'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [OccurredUntilUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261010032839_AddStepTimePrecision'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [StepOrder] int NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261010032839_AddStepTimePrecision'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261010032839_AddStepTimePrecision'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012014606_CaseEntityIndexFitsSqlServer'
)
BEGIN
    DROP INDEX [IX_CaseEntities_CaseId_Type_Value] ON [CaseEntities];
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012014606_CaseEntityIndexFitsSqlServer'
)
BEGIN
    CREATE INDEX [IX_CaseEntities_CaseId_Type] ON [CaseEntities] ([CaseId], [Type]) INCLUDE ([Value]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012014606_CaseEntityIndexFitsSqlServer'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012014606_CaseEntityIndexFitsSqlServer'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012060710_JurisdictionNotices'
)
BEGIN
    CREATE TABLE [JurisdictionNotices] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Jurisdiction] nvarchar(50) NOT NULL,
        [NotifiedAtUtc] datetimeoffset NOT NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_JurisdictionNotices] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_JurisdictionNotices_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012060710_JurisdictionNotices'
)
BEGIN
    CREATE UNIQUE INDEX [IX_JurisdictionNotices_CaseId_Jurisdiction] ON [JurisdictionNotices] ([CaseId], [Jurisdiction]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012060710_JurisdictionNotices'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012060710_JurisdictionNotices'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012153629_NotificationMarks'
)
BEGIN
    CREATE TABLE [NotificationMarks] (
        [Key] nvarchar(450) NOT NULL,
        [SentAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_NotificationMarks] PRIMARY KEY ([Key])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012153629_NotificationMarks'
)
BEGIN
    CREATE INDEX [IX_NotificationMarks_SentAtUtc] ON [NotificationMarks] ([SentAtUtc]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012153629_NotificationMarks'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012153629_NotificationMarks'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012154250_AlertDeliveries'
)
BEGIN
    CREATE TABLE [AlertDeliveries] (
        [Id] uniqueidentifier NOT NULL,
        [Kind] nvarchar(40) NOT NULL,
        [CaseId] uniqueidentifier NULL,
        [CaseNumber] nvarchar(200) NULL,
        [Recipients] nvarchar(4000) NOT NULL,
        [Subject] nvarchar(1000) NOT NULL,
        [HtmlBody] nvarchar(max) NOT NULL,
        [TextBody] nvarchar(max) NOT NULL,
        [FirstFailedAtUtc] datetimeoffset NOT NULL,
        [Retries] int NOT NULL,
        [NextAttemptAtUtc] datetimeoffset NULL,
        [DeliveredAtUtc] datetimeoffset NULL,
        [GaveUpAtUtc] datetimeoffset NULL,
        [DismissedAtUtc] datetimeoffset NULL,
        [DismissedBy] nvarchar(200) NULL,
        CONSTRAINT [PK_AlertDeliveries] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012154250_AlertDeliveries'
)
BEGIN
    CREATE INDEX [IX_AlertDeliveries_CaseId] ON [AlertDeliveries] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012154250_AlertDeliveries'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012154250_AlertDeliveries'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155220_HistoryRowHashes'
)
BEGIN
    ALTER TABLE [StatusChanges] ADD [RowHash] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155220_HistoryRowHashes'
)
BEGIN
    ALTER TABLE [SeverityChanges] ADD [RowHash] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155220_HistoryRowHashes'
)
BEGIN
    ALTER TABLE [MaterialityChanges] ADD [RowHash] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155220_HistoryRowHashes'
)
BEGIN
    ALTER TABLE [EvidenceCitations] ADD [RowHash] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155220_HistoryRowHashes'
)
BEGIN
    ALTER TABLE [EntityVerdictChanges] ADD [RowHash] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155220_HistoryRowHashes'
)
BEGIN
    ALTER TABLE [ClassificationChanges] ADD [RowHash] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155220_HistoryRowHashes'
)
BEGIN
    ALTER TABLE [CaseAssignments] ADD [RowHash] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155220_HistoryRowHashes'
)
BEGIN
    ALTER TABLE [AssignmentChanges] ADD [RowHash] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155220_HistoryRowHashes'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012155220_HistoryRowHashes'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155902_CaseEditVersion'
)
BEGIN
    ALTER TABLE [Cases] ADD [EditVersion] uniqueidentifier NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155902_CaseEditVersion'
)
BEGIN
    EXEC(N'    UPDATE CaseBriefs SET IsCurrent = 0 WHERE IsCurrent = 1 AND EXISTS (SELECT 1 FROM CaseBriefs o WHERE o.CaseId = CaseBriefs.CaseId AND o.IsCurrent = 1 AND (o.Version > CaseBriefs.Version OR (o.Version = CaseBriefs.Version AND o.Id > CaseBriefs.Id)))');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155902_CaseEditVersion'
)
BEGIN
    EXEC(N'CREATE UNIQUE INDEX [IX_CaseBriefs_OneCurrent] ON [CaseBriefs] ([CaseId], [IsCurrent]) WHERE IsCurrent = 1');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012155902_CaseEditVersion'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012155902_CaseEditVersion'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012160816_SealKeyedFrom'
)
BEGIN
    ALTER TABLE [IntegritySeals] ADD [KeyedFromSequence] bigint NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012160816_SealKeyedFrom'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012160816_SealKeyedFrom'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var2 nvarchar(max);
    SELECT @var2 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[TransitionTimeCorrections]') AND [c].[name] = N'RowHash');
    IF @var2 IS NOT NULL EXEC(N'ALTER TABLE [TransitionTimeCorrections] DROP CONSTRAINT ' + @var2 + ';');
    ALTER TABLE [TransitionTimeCorrections] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var3 nvarchar(max);
    SELECT @var3 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[TimelineEntries]') AND [c].[name] = N'RowHash');
    IF @var3 IS NOT NULL EXEC(N'ALTER TABLE [TimelineEntries] DROP CONSTRAINT ' + @var3 + ';');
    ALTER TABLE [TimelineEntries] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var4 nvarchar(max);
    SELECT @var4 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[StatusChanges]') AND [c].[name] = N'RowHash');
    IF @var4 IS NOT NULL EXEC(N'ALTER TABLE [StatusChanges] DROP CONSTRAINT ' + @var4 + ';');
    ALTER TABLE [StatusChanges] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var5 nvarchar(max);
    SELECT @var5 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[StageGates]') AND [c].[name] = N'RowHash');
    IF @var5 IS NOT NULL EXEC(N'ALTER TABLE [StageGates] DROP CONSTRAINT ' + @var5 + ';');
    ALTER TABLE [StageGates] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var6 nvarchar(max);
    SELECT @var6 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[StageGateRequirements]') AND [c].[name] = N'RowHash');
    IF @var6 IS NOT NULL EXEC(N'ALTER TABLE [StageGateRequirements] DROP CONSTRAINT ' + @var6 + ';');
    ALTER TABLE [StageGateRequirements] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var7 nvarchar(max);
    SELECT @var7 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[SeverityChanges]') AND [c].[name] = N'RowHash');
    IF @var7 IS NOT NULL EXEC(N'ALTER TABLE [SeverityChanges] DROP CONSTRAINT ' + @var7 + ';');
    ALTER TABLE [SeverityChanges] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var8 nvarchar(max);
    SELECT @var8 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[Roles]') AND [c].[name] = N'RowHash');
    IF @var8 IS NOT NULL EXEC(N'ALTER TABLE [Roles] DROP CONSTRAINT ' + @var8 + ';');
    ALTER TABLE [Roles] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var9 nvarchar(max);
    SELECT @var9 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[ReportTemplates]') AND [c].[name] = N'RowHash');
    IF @var9 IS NOT NULL EXEC(N'ALTER TABLE [ReportTemplates] DROP CONSTRAINT ' + @var9 + ';');
    ALTER TABLE [ReportTemplates] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var10 nvarchar(max);
    SELECT @var10 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[ReportProfiles]') AND [c].[name] = N'RowHash');
    IF @var10 IS NOT NULL EXEC(N'ALTER TABLE [ReportProfiles] DROP CONSTRAINT ' + @var10 + ';');
    ALTER TABLE [ReportProfiles] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var11 nvarchar(max);
    SELECT @var11 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[PostIncidentReviews]') AND [c].[name] = N'RowHash');
    IF @var11 IS NOT NULL EXEC(N'ALTER TABLE [PostIncidentReviews] DROP CONSTRAINT ' + @var11 + ';');
    ALTER TABLE [PostIncidentReviews] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var12 nvarchar(max);
    SELECT @var12 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[NotificationRules]') AND [c].[name] = N'RowHash');
    IF @var12 IS NOT NULL EXEC(N'ALTER TABLE [NotificationRules] DROP CONSTRAINT ' + @var12 + ';');
    ALTER TABLE [NotificationRules] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var13 nvarchar(max);
    SELECT @var13 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[MaterialityChanges]') AND [c].[name] = N'RowHash');
    IF @var13 IS NOT NULL EXEC(N'ALTER TABLE [MaterialityChanges] DROP CONSTRAINT ' + @var13 + ';');
    ALTER TABLE [MaterialityChanges] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var14 nvarchar(max);
    SELECT @var14 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[JurisdictionNotices]') AND [c].[name] = N'RowHash');
    IF @var14 IS NOT NULL EXEC(N'ALTER TABLE [JurisdictionNotices] DROP CONSTRAINT ' + @var14 + ';');
    ALTER TABLE [JurisdictionNotices] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var15 nvarchar(max);
    SELECT @var15 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[ImprovementActions]') AND [c].[name] = N'RowHash');
    IF @var15 IS NOT NULL EXEC(N'ALTER TABLE [ImprovementActions] DROP CONSTRAINT ' + @var15 + ';');
    ALTER TABLE [ImprovementActions] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var16 nvarchar(max);
    SELECT @var16 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[GatePassages]') AND [c].[name] = N'RowHash');
    IF @var16 IS NOT NULL EXEC(N'ALTER TABLE [GatePassages] DROP CONSTRAINT ' + @var16 + ';');
    ALTER TABLE [GatePassages] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var17 nvarchar(max);
    SELECT @var17 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[EvidenceCitations]') AND [c].[name] = N'RowHash');
    IF @var17 IS NOT NULL EXEC(N'ALTER TABLE [EvidenceCitations] DROP CONSTRAINT ' + @var17 + ';');
    ALTER TABLE [EvidenceCitations] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var18 nvarchar(max);
    SELECT @var18 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[Evidence]') AND [c].[name] = N'RowHash');
    IF @var18 IS NOT NULL EXEC(N'ALTER TABLE [Evidence] DROP CONSTRAINT ' + @var18 + ';');
    ALTER TABLE [Evidence] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var19 nvarchar(max);
    SELECT @var19 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[EntityVerdictChanges]') AND [c].[name] = N'RowHash');
    IF @var19 IS NOT NULL EXEC(N'ALTER TABLE [EntityVerdictChanges] DROP CONSTRAINT ' + @var19 + ';');
    ALTER TABLE [EntityVerdictChanges] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var20 nvarchar(max);
    SELECT @var20 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[EntityRelationships]') AND [c].[name] = N'RowHash');
    IF @var20 IS NOT NULL EXEC(N'ALTER TABLE [EntityRelationships] DROP CONSTRAINT ' + @var20 + ';');
    ALTER TABLE [EntityRelationships] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var21 nvarchar(max);
    SELECT @var21 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[DataElements]') AND [c].[name] = N'RowHash');
    IF @var21 IS NOT NULL EXEC(N'ALTER TABLE [DataElements] DROP CONSTRAINT ' + @var21 + ';');
    ALTER TABLE [DataElements] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var22 nvarchar(max);
    SELECT @var22 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[ClassificationChanges]') AND [c].[name] = N'RowHash');
    IF @var22 IS NOT NULL EXEC(N'ALTER TABLE [ClassificationChanges] DROP CONSTRAINT ' + @var22 + ';');
    ALTER TABLE [ClassificationChanges] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var23 nvarchar(max);
    SELECT @var23 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[CaseTemplateSteps]') AND [c].[name] = N'RowHash');
    IF @var23 IS NOT NULL EXEC(N'ALTER TABLE [CaseTemplateSteps] DROP CONSTRAINT ' + @var23 + ';');
    ALTER TABLE [CaseTemplateSteps] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var24 nvarchar(max);
    SELECT @var24 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[CaseTemplates]') AND [c].[name] = N'RowHash');
    IF @var24 IS NOT NULL EXEC(N'ALTER TABLE [CaseTemplates] DROP CONSTRAINT ' + @var24 + ';');
    ALTER TABLE [CaseTemplates] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var25 nvarchar(max);
    SELECT @var25 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[CaseTechniques]') AND [c].[name] = N'RowHash');
    IF @var25 IS NOT NULL EXEC(N'ALTER TABLE [CaseTechniques] DROP CONSTRAINT ' + @var25 + ';');
    ALTER TABLE [CaseTechniques] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var26 nvarchar(max);
    SELECT @var26 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[Cases]') AND [c].[name] = N'RowHash');
    IF @var26 IS NOT NULL EXEC(N'ALTER TABLE [Cases] DROP CONSTRAINT ' + @var26 + ';');
    ALTER TABLE [Cases] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var27 nvarchar(max);
    SELECT @var27 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[CaseOutcomes]') AND [c].[name] = N'RowHash');
    IF @var27 IS NOT NULL EXEC(N'ALTER TABLE [CaseOutcomes] DROP CONSTRAINT ' + @var27 + ';');
    ALTER TABLE [CaseOutcomes] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var28 nvarchar(max);
    SELECT @var28 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[CaseLinks]') AND [c].[name] = N'RowHash');
    IF @var28 IS NOT NULL EXEC(N'ALTER TABLE [CaseLinks] DROP CONSTRAINT ' + @var28 + ';');
    ALTER TABLE [CaseLinks] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var29 nvarchar(max);
    SELECT @var29 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[CaseEntities]') AND [c].[name] = N'RowHash');
    IF @var29 IS NOT NULL EXEC(N'ALTER TABLE [CaseEntities] DROP CONSTRAINT ' + @var29 + ';');
    ALTER TABLE [CaseEntities] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var30 nvarchar(max);
    SELECT @var30 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[CaseBriefs]') AND [c].[name] = N'RowHash');
    IF @var30 IS NOT NULL EXEC(N'ALTER TABLE [CaseBriefs] DROP CONSTRAINT ' + @var30 + ';');
    ALTER TABLE [CaseBriefs] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var31 nvarchar(max);
    SELECT @var31 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[CaseAssignments]') AND [c].[name] = N'RowHash');
    IF @var31 IS NOT NULL EXEC(N'ALTER TABLE [CaseAssignments] DROP CONSTRAINT ' + @var31 + ';');
    ALTER TABLE [CaseAssignments] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var32 nvarchar(max);
    SELECT @var32 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[AssignmentChanges]') AND [c].[name] = N'RowHash');
    IF @var32 IS NOT NULL EXEC(N'ALTER TABLE [AssignmentChanges] DROP CONSTRAINT ' + @var32 + ';');
    ALTER TABLE [AssignmentChanges] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var33 nvarchar(max);
    SELECT @var33 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[AppSettings]') AND [c].[name] = N'RowHash');
    IF @var33 IS NOT NULL EXEC(N'ALTER TABLE [AppSettings] DROP CONSTRAINT ' + @var33 + ';');
    ALTER TABLE [AppSettings] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var34 nvarchar(max);
    SELECT @var34 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[AnalystNotes]') AND [c].[name] = N'RowHash');
    IF @var34 IS NOT NULL EXEC(N'ALTER TABLE [AnalystNotes] DROP CONSTRAINT ' + @var34 + ';');
    ALTER TABLE [AnalystNotes] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var35 nvarchar(max);
    SELECT @var35 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[AdGroupRoleMappings]') AND [c].[name] = N'RowHash');
    IF @var35 IS NOT NULL EXEC(N'ALTER TABLE [AdGroupRoleMappings] DROP CONSTRAINT ' + @var35 + ';');
    ALTER TABLE [AdGroupRoleMappings] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var36 nvarchar(max);
    SELECT @var36 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[ActionItems]') AND [c].[name] = N'RowHash');
    IF @var36 IS NOT NULL EXEC(N'ALTER TABLE [ActionItems] DROP CONSTRAINT ' + @var36 + ';');
    ALTER TABLE [ActionItems] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    DECLARE @var37 nvarchar(max);
    SELECT @var37 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[ActionItemComments]') AND [c].[name] = N'RowHash');
    IF @var37 IS NOT NULL EXEC(N'ALTER TABLE [ActionItemComments] DROP CONSTRAINT ' + @var37 + ';');
    ALTER TABLE [ActionItemComments] ALTER COLUMN [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012161613_RowHashFormat2'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012161613_RowHashFormat2'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012172622_PendingImportResume'
)
BEGIN
    ALTER TABLE [PendingImports] ADD [ResumeJson] nvarchar(max) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012172622_PendingImportResume'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012172622_PendingImportResume'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012173001_NotificationMarkConfirmed'
)
BEGIN
    ALTER TABLE [NotificationMarks] ADD [ConfirmedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012173001_NotificationMarkConfirmed'
)
BEGIN
    EXEC(N'    UPDATE NotificationMarks SET ConfirmedAtUtc = SentAtUtc');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012173001_NotificationMarkConfirmed'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012173001_NotificationMarkConfirmed'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012180740_ContainmentNotNeeded'
)
BEGIN
    ALTER TABLE [Cases] ADD [ContainmentNotNeededReason] nvarchar(1000) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012180740_ContainmentNotNeeded'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012180740_ContainmentNotNeeded'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012183347_AuditEntryFormat'
)
BEGIN
    ALTER TABLE [AuditLog] ADD [Format] int NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012183347_AuditEntryFormat'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012183347_AuditEntryFormat'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012183715_CaseBriefLatestCurrent'
)
BEGIN
    EXEC(N'    UPDATE CaseBriefs SET IsCurrent = 0 WHERE IsCurrent = 1 AND NOT EXISTS (SELECT 1 FROM CaseBriefs h WHERE h.CaseId = CaseBriefs.CaseId AND h.Version > CaseBriefs.Version) AND EXISTS (SELECT 1 FROM CaseBriefs o WHERE o.CaseId = CaseBriefs.CaseId AND o.IsCurrent = 0 AND o.Version = CaseBriefs.Version AND (o.CreatedAtUtc > CaseBriefs.CreatedAtUtc OR (o.CreatedAtUtc = CaseBriefs.CreatedAtUtc AND o.Id > CaseBriefs.Id)))');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012183715_CaseBriefLatestCurrent'
)
BEGIN
    EXEC(N'    UPDATE CaseBriefs SET IsCurrent = 1 WHERE NOT EXISTS (SELECT 1 FROM CaseBriefs c WHERE c.CaseId = CaseBriefs.CaseId AND c.IsCurrent = 1) AND NOT EXISTS (SELECT 1 FROM CaseBriefs o WHERE o.CaseId = CaseBriefs.CaseId AND (o.Version > CaseBriefs.Version OR (o.Version = CaseBriefs.Version AND (o.CreatedAtUtc > CaseBriefs.CreatedAtUtc OR (o.CreatedAtUtc = CaseBriefs.CreatedAtUtc AND o.Id > CaseBriefs.Id)))))');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012183715_CaseBriefLatestCurrent'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012183715_CaseBriefLatestCurrent'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012205203_AuditLogEntityIndex'
)
BEGIN
    CREATE INDEX [IX_AuditLog_EntityType_EntityId] ON [AuditLog] ([EntityType], [EntityId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012205203_AuditLogEntityIndex'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012205203_AuditLogEntityIndex'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012212238_UserRolesWider'
)
BEGIN
    DECLARE @var38 nvarchar(max);
    SELECT @var38 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[Users]') AND [c].[name] = N'RolesCsv');
    IF @var38 IS NOT NULL EXEC(N'ALTER TABLE [Users] DROP CONSTRAINT ' + @var38 + ';');
    ALTER TABLE [Users] ALTER COLUMN [RolesCsv] nvarchar(4000) NOT NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261012212238_UserRolesWider'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261012212238_UserRolesWider'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261013005522_ApiTokenRolesWider'
)
BEGIN
    DECLARE @var39 nvarchar(max);
    SELECT @var39 = QUOTENAME([d].[name])
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[ApiTokens]') AND [c].[name] = N'RolesCsv');
    IF @var39 IS NOT NULL EXEC(N'ALTER TABLE [ApiTokens] DROP CONSTRAINT ' + @var39 + ';');
    ALTER TABLE [ApiTokens] ALTER COLUMN [RolesCsv] nvarchar(4000) NOT NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261013005522_ApiTokenRolesWider'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261013005522_ApiTokenRolesWider'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261013040758_ApiTokenRowHash'
)
BEGIN
    ALTER TABLE [ApiTokens] ADD [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261013040758_ApiTokenRowHash'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261013040758_ApiTokenRowHash'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261013124330_ReportedJurisdictionsAndAppendedBriefs'
)
BEGIN
    ALTER TABLE [Cases] ADD [ReportedJurisdictions] nvarchar(1000) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261013124330_ReportedJurisdictionsAndAppendedBriefs'
)
BEGIN
    ALTER TABLE [CaseBriefs] ADD [Appended] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261013124330_ReportedJurisdictionsAndAppendedBriefs'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261013124330_ReportedJurisdictionsAndAppendedBriefs'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261013132953_PendingImportHash'
)
BEGIN
    ALTER TABLE [PendingImports] ADD [RawJsonSha256] nvarchar(64) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261013132953_PendingImportHash'
)
BEGIN
    CREATE INDEX [IX_PendingImports_SubmittedBy_RawJsonSha256] ON [PendingImports] ([SubmittedBy], [RawJsonSha256]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261013132953_PendingImportHash'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261013132953_PendingImportHash'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014022525_NoticeDueAt'
)
BEGIN
    ALTER TABLE [JurisdictionNotices] ADD [DueAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014022525_NoticeDueAt'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261014022525_NoticeDueAt'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014113100_TaskCompletionRecordedAt'
)
BEGIN
    ALTER TABLE [ActionItems] ADD [CompletionRecordedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014113100_TaskCompletionRecordedAt'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261014113100_TaskCompletionRecordedAt'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014160350_AccountDirectorySnapshots'
)
BEGIN
    CREATE TABLE [AccountDirectorySnapshots] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [EntityId] uniqueidentifier NOT NULL,
        [LookedUp] nvarchar(400) NOT NULL,
        [Trigger] int NOT NULL,
        [Found] bit NOT NULL,
        [SamAccountName] nvarchar(256) NULL,
        [UserPrincipalName] nvarchar(400) NULL,
        [DisplayName] nvarchar(400) NULL,
        [Title] nvarchar(400) NULL,
        [Department] nvarchar(400) NULL,
        [Manager] nvarchar(400) NULL,
        [Email] nvarchar(400) NULL,
        [DistinguishedName] nvarchar(1000) NULL,
        [Enabled] bit NULL,
        [LockedOut] bit NULL,
        [AccountExpiresUtc] datetimeoffset NULL,
        [LastLogonUtc] datetimeoffset NULL,
        [PasswordLastSetUtc] datetimeoffset NULL,
        [WhenCreatedUtc] datetimeoffset NULL,
        [RowHash] nvarchar(70) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(200) NULL,
        CONSTRAINT [PK_AccountDirectorySnapshots] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014160350_AccountDirectorySnapshots'
)
BEGIN
    CREATE INDEX [IX_AccountDirectorySnapshots_CaseId_EntityId] ON [AccountDirectorySnapshots] ([CaseId], [EntityId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014160350_AccountDirectorySnapshots'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261014160350_AccountDirectorySnapshots'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014161055_RetractEntriesAndVerdictTimes'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [RetractReason] nvarchar(2000) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014161055_RetractEntriesAndVerdictTimes'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [RetractedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014161055_RetractEntriesAndVerdictTimes'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [RetractedBy] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014161055_RetractEntriesAndVerdictTimes'
)
BEGIN
    ALTER TABLE [EntityVerdictChanges] ADD [EffectiveAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261014161055_RetractEntriesAndVerdictTimes'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261014161055_RetractEntriesAndVerdictTimes'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261016201631_HeldEmails'
)
BEGIN
    CREATE TABLE [HeldEmails] (
        [Id] bigint NOT NULL IDENTITY,
        [Recipients] nvarchar(max) NOT NULL,
        [Subject] nvarchar(max) NOT NULL,
        [TextBody] nvarchar(max) NOT NULL,
        [HtmlBody] nvarchar(max) NULL,
        [HeldAtUtc] datetimeoffset NOT NULL,
        [Attempts] int NOT NULL,
        CONSTRAINT [PK_HeldEmails] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261016201631_HeldEmails'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261016201631_HeldEmails'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261016210523_ReportRowHash'
)
BEGIN
    ALTER TABLE [Reports] ADD [RowHash] nvarchar(70) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261016210523_ReportRowHash'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261016210523_ReportRowHash'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261017003452_HeldEmailRetryAndAudience'
)
BEGIN
    ALTER TABLE [HeldEmails] ADD [CaseId] uniqueidentifier NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261017003452_HeldEmailRetryAndAudience'
)
BEGIN
    ALTER TABLE [HeldEmails] ADD [NextAttemptAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261017003452_HeldEmailRetryAndAudience'
)
BEGIN
    ALTER TABLE [HeldEmails] ADD [RecipientUserIds] nvarchar(max) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261017003452_HeldEmailRetryAndAudience'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261017003452_HeldEmailRetryAndAudience'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261017165615_EvidenceKeyEnvelopes'
)
BEGIN
    CREATE TABLE [KeyEnvelopes] (
        [KeyId] nvarchar(16) NOT NULL,
        [EnvelopeJson] nvarchar(max) NOT NULL,
        [UpdatedAtUtc] datetimeoffset NOT NULL,
        CONSTRAINT [PK_KeyEnvelopes] PRIMARY KEY ([KeyId])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261017165615_EvidenceKeyEnvelopes'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261017165615_EvidenceKeyEnvelopes'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018035849_SmtpSignIn'
)
BEGIN
    CREATE TABLE [SmtpSignIns] (
        [Id] int NOT NULL,
        [Mode] nvarchar(16) NOT NULL,
        [Username] nvarchar(256) NOT NULL,
        [ProtectedPassword] nvarchar(max) NULL,
        [PasswordSetAtUtc] datetimeoffset NULL,
        [PasswordSetBy] nvarchar(256) NULL,
        [UpdatedAtUtc] datetimeoffset NOT NULL,
        [UpdatedBy] nvarchar(256) NOT NULL,
        CONSTRAINT [PK_SmtpSignIns] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018035849_SmtpSignIn'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261018035849_SmtpSignIn'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018053605_StoredSecrets'
)
BEGIN
    CREATE TABLE [StoredSecrets] (
        [Name] nvarchar(64) NOT NULL,
        [ProtectedValue] nvarchar(max) NULL,
        [SetAtUtc] datetimeoffset NULL,
        [SetBy] nvarchar(256) NULL,
        [UpdatedAtUtc] datetimeoffset NOT NULL,
        [UpdatedBy] nvarchar(256) NOT NULL,
        CONSTRAINT [PK_StoredSecrets] PRIMARY KEY ([Name])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018053605_StoredSecrets'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261018053605_StoredSecrets'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018054208_NoticeDetails'
)
BEGIN
    ALTER TABLE [JurisdictionNotices] ADD [EvidenceId] uniqueidentifier NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018054208_NoticeDetails'
)
BEGIN
    ALTER TABLE [JurisdictionNotices] ADD [Method] int NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018054208_NoticeDetails'
)
BEGIN
    ALTER TABLE [JurisdictionNotices] ADD [NotifiedBy] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018054208_NoticeDetails'
)
BEGIN
    ALTER TABLE [JurisdictionNotices] ADD [Reference] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018054208_NoticeDetails'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261018054208_NoticeDetails'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018062258_EvidenceCollection'
)
BEGIN
    ALTER TABLE [Evidence] ADD [CollectedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018062258_EvidenceCollection'
)
BEGIN
    ALTER TABLE [Evidence] ADD [CollectedBy] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018062258_EvidenceCollection'
)
BEGIN
    ALTER TABLE [Evidence] ADD [CollectedFrom] nvarchar(300) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018062258_EvidenceCollection'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261018062258_EvidenceCollection'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018071458_EvidenceWithdrawal'
)
BEGIN
    ALTER TABLE [Evidence] ADD [WithdrawnAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018071458_EvidenceWithdrawal'
)
BEGIN
    ALTER TABLE [Evidence] ADD [WithdrawnBy] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018071458_EvidenceWithdrawal'
)
BEGIN
    ALTER TABLE [Evidence] ADD [WithdrawnReason] nvarchar(2000) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018071458_EvidenceWithdrawal'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261018071458_EvidenceWithdrawal'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018080718_HandoffRecipient'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [HandedToUserId] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018080718_HandoffRecipient'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261018080718_HandoffRecipient'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018090013_AddCaseParties'
)
BEGIN
    CREATE TABLE [CaseParties] (
        [Id] uniqueidentifier NOT NULL,
        [CaseId] uniqueidentifier NOT NULL,
        [Role] int NOT NULL,
        [Name] nvarchar(300) NOT NULL,
        [Contact] nvarchar(300) NULL,
        [Reference] nvarchar(200) NULL,
        [EngagedAtUtc] datetimeoffset NULL,
        [Notes] nvarchar(2000) NULL,
        [RowHash] nvarchar(70) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(200) NULL,
        CONSTRAINT [PK_CaseParties] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_CaseParties_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018090013_AddCaseParties'
)
BEGIN
    CREATE INDEX [IX_CaseParties_CaseId] ON [CaseParties] ([CaseId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018090013_AddCaseParties'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261018090013_AddCaseParties'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018130609_AddTeams'
)
BEGIN
    ALTER TABLE [SavedViews] ADD [TeamId] uniqueidentifier NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018130609_AddTeams'
)
BEGIN
    ALTER TABLE [Cases] ADD [TeamId] uniqueidentifier NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018130609_AddTeams'
)
BEGIN
    CREATE TABLE [Teams] (
        [Id] uniqueidentifier NOT NULL,
        [Key] nvarchar(40) NOT NULL,
        [Name] nvarchar(100) NOT NULL,
        [IsActive] bit NOT NULL,
        [DetectionSourceLabel] nvarchar(60) NULL,
        [DetectionLinkTemplate] nvarchar(500) NULL,
        [RowHash] nvarchar(70) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(200) NULL,
        CONSTRAINT [PK_Teams] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018130609_AddTeams'
)
BEGIN
    CREATE TABLE [TeamMembers] (
        [Id] uniqueidentifier NOT NULL,
        [TeamId] uniqueidentifier NOT NULL,
        [UserId] nvarchar(200) NOT NULL,
        [AddedAtUtc] datetimeoffset NOT NULL,
        [AddedBy] nvarchar(200) NOT NULL,
        [RowHash] nvarchar(70) NULL,
        CONSTRAINT [PK_TeamMembers] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_TeamMembers_Teams_TeamId] FOREIGN KEY ([TeamId]) REFERENCES [Teams] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018130609_AddTeams'
)
BEGIN
    CREATE INDEX [IX_SavedViews_TeamId] ON [SavedViews] ([TeamId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018130609_AddTeams'
)
BEGIN
    CREATE INDEX [IX_Cases_TeamId] ON [Cases] ([TeamId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018130609_AddTeams'
)
BEGIN
    CREATE UNIQUE INDEX [IX_TeamMembers_TeamId_UserId] ON [TeamMembers] ([TeamId], [UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018130609_AddTeams'
)
BEGIN
    CREATE INDEX [IX_TeamMembers_UserId] ON [TeamMembers] ([UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018130609_AddTeams'
)
BEGIN
    CREATE UNIQUE INDEX [IX_Teams_Key] ON [Teams] ([Key]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018130609_AddTeams'
)
BEGIN
    CREATE UNIQUE INDEX [IX_Teams_Name] ON [Teams] ([Name]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018130609_AddTeams'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261018130609_AddTeams'', N''10.0.13'');');
END;

COMMIT;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018131002_FullTextSearch'
)
BEGIN

    -- CAP-22: CaseBook's full-text catalog and indexes. Creates only what's missing, and nothing when the server
    -- doesn't have Full-Text Search, so it can be run again at any time. Not inside a transaction.
    IF CAST(ISNULL(SERVERPROPERTY('IsFullTextInstalled'), 0) AS int) = 1
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM sys.fulltext_catalogs WHERE name = N'CaseBookText')
            EXEC(N'CREATE FULLTEXT CATALOG [CaseBookText]');
        IF OBJECT_ID(N'[Cases]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Cases]'))
            EXEC(N'CREATE FULLTEXT INDEX ON [Cases] ([Title] LANGUAGE 1033, [Summary] LANGUAGE 1033) KEY INDEX [PK_Cases] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Cases]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[Cases]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[Cases]'), N'Title', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [Cases] ADD ([Title] LANGUAGE 1033)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Cases]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[Cases]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[Cases]'), N'Summary', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [Cases] ADD ([Summary] LANGUAGE 1033)');
        IF OBJECT_ID(N'[CaseBriefs]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[CaseBriefs]'))
            EXEC(N'CREATE FULLTEXT INDEX ON [CaseBriefs] ([Summary] LANGUAGE 1033, [WorkingAssessment] LANGUAGE 1033, [Known] LANGUAGE 1033, [OpenQuestions] LANGUAGE 1033) KEY INDEX [PK_CaseBriefs] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[CaseBriefs]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[CaseBriefs]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[CaseBriefs]'), N'Summary', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [CaseBriefs] ADD ([Summary] LANGUAGE 1033)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[CaseBriefs]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[CaseBriefs]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[CaseBriefs]'), N'WorkingAssessment', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [CaseBriefs] ADD ([WorkingAssessment] LANGUAGE 1033)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[CaseBriefs]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[CaseBriefs]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[CaseBriefs]'), N'Known', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [CaseBriefs] ADD ([Known] LANGUAGE 1033)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[CaseBriefs]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[CaseBriefs]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[CaseBriefs]'), N'OpenQuestions', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [CaseBriefs] ADD ([OpenQuestions] LANGUAGE 1033)');
        IF OBJECT_ID(N'[TimelineEntries]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[TimelineEntries]'))
            EXEC(N'CREATE FULLTEXT INDEX ON [TimelineEntries] ([Description] LANGUAGE 1033, [Rationale] LANGUAGE 1033) KEY INDEX [PK_TimelineEntries] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[TimelineEntries]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[TimelineEntries]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[TimelineEntries]'), N'Description', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [TimelineEntries] ADD ([Description] LANGUAGE 1033)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[TimelineEntries]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[TimelineEntries]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[TimelineEntries]'), N'Rationale', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [TimelineEntries] ADD ([Rationale] LANGUAGE 1033)');
        IF OBJECT_ID(N'[AnalystNotes]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[AnalystNotes]'))
            EXEC(N'CREATE FULLTEXT INDEX ON [AnalystNotes] ([Body] LANGUAGE 1033) KEY INDEX [PK_AnalystNotes] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[AnalystNotes]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[AnalystNotes]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[AnalystNotes]'), N'Body', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [AnalystNotes] ADD ([Body] LANGUAGE 1033)');
        IF OBJECT_ID(N'[ActionItems]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItems]'))
            EXEC(N'CREATE FULLTEXT INDEX ON [ActionItems] ([Title] LANGUAGE 1033, [Description] LANGUAGE 1033) KEY INDEX [PK_ActionItems] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItems]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[ActionItems]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[ActionItems]'), N'Title', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [ActionItems] ADD ([Title] LANGUAGE 1033)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItems]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[ActionItems]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[ActionItems]'), N'Description', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [ActionItems] ADD ([Description] LANGUAGE 1033)');
        IF OBJECT_ID(N'[ActionItemComments]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItemComments]'))
            EXEC(N'CREATE FULLTEXT INDEX ON [ActionItemComments] ([Body] LANGUAGE 1033) KEY INDEX [PK_ActionItemComments] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[ActionItemComments]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[ActionItemComments]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[ActionItemComments]'), N'Body', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [ActionItemComments] ADD ([Body] LANGUAGE 1033)');
        IF OBJECT_ID(N'[Evidence]') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Evidence]'))
            EXEC(N'CREATE FULLTEXT INDEX ON [Evidence] ([Description] LANGUAGE 1033) KEY INDEX [PK_Evidence] ON [CaseBookText] WITH (CHANGE_TRACKING = AUTO, STOPLIST = OFF)');
        IF EXISTS (SELECT 1 FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID(N'[Evidence]'))
           AND NOT EXISTS (SELECT 1 FROM sys.fulltext_index_columns WHERE object_id = OBJECT_ID(N'[Evidence]') AND column_id = COLUMNPROPERTY(OBJECT_ID(N'[Evidence]'), N'Description', 'ColumnId'))
            EXEC(N'ALTER FULLTEXT INDEX ON [Evidence] ADD ([Description] LANGUAGE 1033)');
    END;

END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261018131002_FullTextSearch'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261018131002_FullTextSearch'', N''10.0.13'');');
END;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261020203221_EvidencePurge'
)
BEGIN
    ALTER TABLE [Evidence] ADD [PurgedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261020203221_EvidencePurge'
)
BEGIN
    ALTER TABLE [Evidence] ADD [PurgedBy] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261020203221_EvidencePurge'
)
BEGIN
    ALTER TABLE [Evidence] ADD [PurgedReason] nvarchar(2000) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261020203221_EvidencePurge'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261020203221_EvidencePurge'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261021022219_ContainedBy'
)
BEGIN
    ALTER TABLE [Cases] ADD [ContainedBy] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261021022219_ContainedBy'
)
BEGIN
    ALTER TABLE [Cases] ADD [ContainedRecordedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261021022219_ContainedBy'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261021022219_ContainedBy'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261021193542_CaseRemoval'
)
BEGIN
    ALTER TABLE [Cases] ADD [PurgedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261021193542_CaseRemoval'
)
BEGIN
    ALTER TABLE [Cases] ADD [RemovedAtUtc] datetimeoffset NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261021193542_CaseRemoval'
)
BEGIN
    ALTER TABLE [Cases] ADD [RemovedBy] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261021193542_CaseRemoval'
)
BEGIN
    ALTER TABLE [Cases] ADD [RemovedNumber] nvarchar(200) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261021193542_CaseRemoval'
)
BEGIN
    ALTER TABLE [Cases] ADD [RemovedReason] nvarchar(1000) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261021193542_CaseRemoval'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261021193542_CaseRemoval'', N''10.0.13'');');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261023161028_TimelineEntryMoreScreenshots'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [MoreEvidenceIds] nvarchar(400) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261023161028_TimelineEntryMoreScreenshots'
)
BEGIN
    EXEC(N'    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N''20261023161028_TimelineEntryMoreScreenshots'', N''10.0.13'');');
END;

COMMIT;
GO

