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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE TABLE [Cases] (
        [Id] uniqueidentifier NOT NULL,
        [Year] int NOT NULL,
        [Sequence] int NOT NULL,
        [DescriptiveName] nvarchar(200) NOT NULL,
        [CaseNumber] nvarchar(200) NOT NULL,
        [Title] nvarchar(300) NOT NULL,
        [Classification] int NOT NULL,
        [Phase] int NOT NULL,
        [Severity] int NOT NULL,
        [Origin] int NOT NULL,
        [Summary] nvarchar(max) NULL,
        [ImpactedAssets] nvarchar(4000) NULL,
        [DataTypesInvolved] nvarchar(4000) NULL,
        [AffectedIndividualsCount] int NULL,
        [DataElements] int NOT NULL,
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_ActionItems_CaseId_Status] ON [ActionItems] ([CaseId], [Status]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_AdGroupRoleMappings_AdGroup_RoleName] ON [AdGroupRoleMappings] ([AdGroup], [RoleName]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AdGroupRoleMappings_RoleName] ON [AdGroupRoleMappings] ([RoleName]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AnalystNotes_CaseId_IsCurrent] ON [AnalystNotes] ([CaseId], [IsCurrent]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_AppSettings_Key] ON [AppSettings] ([Key]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AuditLog_AtUtc] ON [AuditLog] ([AtUtc]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AuditLog_CaseNumber] ON [AuditLog] ([CaseNumber]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_AuditLog_Sequence] ON [AuditLog] ([Sequence]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_CaseAssignments_CaseId_UserId] ON [CaseAssignments] ([CaseId], [UserId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseAssignments_UserId] ON [CaseAssignments] ([UserId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseEntities_CaseId] ON [CaseEntities] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseEntities_CaseId_Type_Value] ON [CaseEntities] ([CaseId], [Type], [Value]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseLinks_CaseId] ON [CaseLinks] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_CaseLinks_CaseId_RelatedCaseId_Type] ON [CaseLinks] ([CaseId], [RelatedCaseId], [Type]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseLinks_RelatedCaseId] ON [CaseLinks] ([RelatedCaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseTechniques_CaseId] ON [CaseTechniques] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_CaseTechniques_CaseId_TechniqueId] ON [CaseTechniques] ([CaseId], [TechniqueId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_CaseTemplateSteps_TemplateId] ON [CaseTemplateSteps] ([TemplateId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_CaseTemplates_Name] ON [CaseTemplates] ([Name]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_Cases_CaseNumber] ON [Cases] ([CaseNumber]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Cases_Classification] ON [Cases] ([Classification]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Cases_IsArchived] ON [Cases] ([IsArchived]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Cases_Phase] ON [Cases] ([Phase]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_Cases_Year_Sequence] ON [Cases] ([Year], [Sequence]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_ChainOfCustodyEvents_EvidenceId] ON [ChainOfCustodyEvents] ([EvidenceId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_ClassificationChanges_CaseId] ON [ClassificationChanges] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_EntityLayouts_CaseId] ON [EntityLayouts] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_EntityLayouts_EntityId] ON [EntityLayouts] ([EntityId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_EntityRelationships_CaseId] ON [EntityRelationships] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_EntityRelationships_SourceEntityId] ON [EntityRelationships] ([SourceEntityId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_EntityRelationships_TargetEntityId] ON [EntityRelationships] ([TargetEntityId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_EventStepTactics_TimelineEntryId] ON [EventStepTactics] ([TimelineEntryId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Evidence_CaseId] ON [Evidence] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Evidence_Sha256] ON [Evidence] ([Sha256]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_IntegritySeals_SealedAtUtc] ON [IntegritySeals] ([SealedAtUtc]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Reports_CaseId] ON [Reports] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_Roles_Name] ON [Roles] ([Name]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_SeverityChanges_CaseId] ON [SeverityChanges] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_StatusChanges_CaseId] ON [StatusChanges] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_TimelineEntries_ActorEntityId] ON [TimelineEntries] ([ActorEntityId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_TimelineEntries_CaseId] ON [TimelineEntries] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_TimelineEntries_CaseId_Kind_IsCurrent] ON [TimelineEntries] ([CaseId], [Kind], [IsCurrent]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_TimelineEntries_OccurredAtUtc] ON [TimelineEntries] ([OccurredAtUtc]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_TimelineEntries_TargetEntityId] ON [TimelineEntries] ([TargetEntityId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_Users_Sid] ON [Users] ([Sid]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260815005408_InitialCreate'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260815005408_InitialCreate', N'8.0.30');
END;
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260816213314_AddComplexEventIntake'
)
BEGIN
    DECLARE @var0 sysname;
    SELECT @var0 = [d].[name]
    FROM [sys].[default_constraints] [d]
    INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
    WHERE ([d].[parent_object_id] = OBJECT_ID(N'[Cases]') AND [c].[name] = N'Classification');
    IF @var0 IS NOT NULL EXEC(N'ALTER TABLE [Cases] DROP CONSTRAINT [' + @var0 + '];');
    ALTER TABLE [Cases] ALTER COLUMN [Classification] int NULL;
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260816213314_AddComplexEventIntake'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260816213314_AddComplexEventIntake', N'8.0.30');
END;
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260816222923_AddStageGates'
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
        [Detail] nvarchar(max) NOT NULL,
        [RowHash] nvarchar(64) NULL,
        CONSTRAINT [PK_GatePassages] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_GatePassages_Cases_CaseId] FOREIGN KEY ([CaseId]) REFERENCES [Cases] ([Id]) ON DELETE CASCADE
    );
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260816222923_AddStageGates'
)
BEGIN
    CREATE TABLE [StageGates] (
        [Id] uniqueidentifier NOT NULL,
        [Trigger] int NOT NULL,
        [IsActive] bit NOT NULL,
        [Name] nvarchar(200) NOT NULL,
        [Description] nvarchar(2000) NULL,
        [RowHash] nvarchar(64) NULL,
        [CreatedAtUtc] datetimeoffset NOT NULL,
        [CreatedBy] nvarchar(200) NOT NULL,
        [ModifiedAtUtc] datetimeoffset NULL,
        [ModifiedBy] nvarchar(max) NULL,
        CONSTRAINT [PK_StageGates] PRIMARY KEY ([Id])
    );
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260816222923_AddStageGates'
)
BEGIN
    CREATE TABLE [StageGateRequirements] (
        [Id] uniqueidentifier NOT NULL,
        [GateId] uniqueidentifier NOT NULL,
        [Order] int NOT NULL,
        [Kind] int NOT NULL,
        [Check] int NULL,
        [Label] nvarchar(400) NOT NULL,
        [IsBlocking] bit NOT NULL,
        [RowHash] nvarchar(64) NULL,
        CONSTRAINT [PK_StageGateRequirements] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_StageGateRequirements_StageGates_GateId] FOREIGN KEY ([GateId]) REFERENCES [StageGates] ([Id]) ON DELETE CASCADE
    );
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260816222923_AddStageGates'
)
BEGIN
    CREATE INDEX [IX_GatePassages_CaseId] ON [GatePassages] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260816222923_AddStageGates'
)
BEGIN
    CREATE INDEX [IX_StageGateRequirements_GateId] ON [StageGateRequirements] ([GateId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260816222923_AddStageGates'
)
BEGIN
    CREATE INDEX [IX_StageGates_Trigger_IsActive] ON [StageGates] ([Trigger], [IsActive]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260816222923_AddStageGates'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260816222923_AddStageGates', N'8.0.30');
END;
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260823170758_AddCaseNumberScheme'
)
BEGIN
    DROP INDEX [IX_Cases_Year_Sequence] ON [Cases];
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260823170758_AddCaseNumberScheme'
)
BEGIN
    ALTER TABLE [Cases] ADD [HasCustomNumber] bit NOT NULL DEFAULT CAST(0 AS bit);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260823170758_AddCaseNumberScheme'
)
BEGIN
    CREATE INDEX [IX_Cases_Year_Sequence] ON [Cases] ([Year], [Sequence]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260823170758_AddCaseNumberScheme'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260823170758_AddCaseNumberScheme', N'8.0.30');
END;
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260823220525_HardenCaseSequenceUniqueness'
)
BEGIN
    DROP INDEX [IX_Cases_Year_Sequence] ON [Cases];
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260823220525_HardenCaseSequenceUniqueness'
)
BEGIN
    EXEC(N'CREATE UNIQUE INDEX [IX_Cases_CeSequence] ON [Cases] ([Year], [Sequence]) WHERE Classification IS NULL AND HasCustomNumber = 0');
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260823220525_HardenCaseSequenceUniqueness'
)
BEGIN
    EXEC(N'CREATE UNIQUE INDEX [IX_Cases_IrpSequence] ON [Cases] ([Year], [Sequence]) WHERE Classification IS NOT NULL AND HasCustomNumber = 0');
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260823220525_HardenCaseSequenceUniqueness'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260823220525_HardenCaseSequenceUniqueness', N'8.0.30');
END;
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824012524_ComplexEventDateNumber'
)
BEGIN
    DROP INDEX [IX_Cases_CeSequence] ON [Cases];
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824012524_ComplexEventDateNumber'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260824012524_ComplexEventDateNumber', N'8.0.30');
END;
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824032316_AddCaseAccessLog'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824032316_AddCaseAccessLog'
)
BEGIN
    CREATE INDEX [IX_CaseAccessEvents_ActorUserId_CaseId_AccessType_LastSeenUtc] ON [CaseAccessEvents] ([ActorUserId], [CaseId], [AccessType], [LastSeenUtc]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824032316_AddCaseAccessLog'
)
BEGIN
    CREATE INDEX [IX_CaseAccessEvents_CaseId] ON [CaseAccessEvents] ([CaseId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824032316_AddCaseAccessLog'
)
BEGIN
    CREATE INDEX [IX_CaseAccessEvents_LastSeenUtc] ON [CaseAccessEvents] ([LastSeenUtc]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824032316_AddCaseAccessLog'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260824032316_AddCaseAccessLog', N'8.0.30');
END;
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824163643_AddReportProfiles'
)
BEGIN
    ALTER TABLE [Cases] ADD [ReportProfileId] uniqueidentifier NULL;
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824163643_AddReportProfiles'
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
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824163643_AddReportProfiles'
)
BEGIN
    CREATE UNIQUE INDEX [IX_ReportProfiles_Name] ON [ReportProfiles] ([Name]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824163643_AddReportProfiles'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260824163643_AddReportProfiles', N'8.0.30');
END;
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824191648_AddTimelineEntryEvidence'
)
BEGIN
    ALTER TABLE [TimelineEntries] ADD [EvidenceId] uniqueidentifier NULL;
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260824191648_AddTimelineEntryEvidence'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260824191648_AddTimelineEntryEvidence', N'8.0.30');
END;
GO

COMMIT;
GO

