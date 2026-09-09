namespace IncidentManager.Domain.Enums;

/// <summary>Which of a case's two timelines an entry belongs to.</summary>
public enum TimelineKind
{
    /// <summary>Facts and timing of the actual event (what happened, when).</summary>
    Event = 0,

    /// <summary>Analyst/team actions taken during the investigation.</summary>
    Investigation = 1
}

/// <summary>Category of a timeline entry, used for filtering the log.</summary>
public enum TimelineEntryType
{
    Detection = 0,
    Analysis = 1,
    Containment = 2,
    Eradication = 3,
    Recovery = 4,
    Communication = 5,
    Evidence = 6,
    Escalation = 7,
    Note = 8,
    Other = 9
}

/// <summary>Status of an after-action follow-up item.</summary>
public enum ActionItemStatus
{
    Open = 0,
    InProgress = 1,
    Blocked = 2,
    Done = 3,
    Cancelled = 4
}

/// <summary>A user's role within a specific case (distinct from their app-wide role).</summary>
public enum CaseAssignmentRole
{
    IncidentCommander = 0,
    Analyst = 1,
    Observer = 2
}

/// <summary>
/// The kind of artifact / observable (IOC) associated with a case, mirroring the entity
/// types an analyst works with in SIEM (accounts, hosts, IPs, hashes, URLs, etc.).
/// </summary>
public enum EntityType
{
    Account = 0,        // user / service account
    Host = 1,           // computer / workstation / server
    IpAddress = 2,
    Domain = 3,
    Url = 4,
    FileHash = 5,       // MD5 / SHA-1 / SHA-256
    FileName = 6,
    EmailAddress = 7,
    Process = 8,
    RegistryKey = 9,
    Other = 10
}

/// <summary>Analyst verdict on an entity — how it relates to the threat.</summary>
public enum EntityDisposition
{
    Unknown = 0,
    Benign = 1,      // e.g. a victim asset confirmed clean
    Suspicious = 2,
    Malicious = 3    // a confirmed IOC
}

/// <summary>
/// A directed relationship between two case entities (source → target), letting analysts
/// build the investigation graph, e.g. an account <c>LoggedInTo</c> a host, a host
/// <c>CommunicatedWith</c> an IP, a URL <c>ResolvedTo</c> an IP.
/// </summary>
public enum EntityRelationshipType
{
    RelatedTo = 0,
    CommunicatedWith = 1,
    ConnectedTo = 2,
    ResolvedTo = 3,
    LoggedInTo = 4,
    Executed = 5,
    Downloaded = 6,
    Dropped = 7,
    Contacted = 8,
    Contains = 9,
    Redirected = 10,
    ChildOf = 11,
    Accessed = 12,
    Impersonated = 13
}

/// <summary>
/// How one case relates to another (E-14 case linking / campaign grouping). <see cref="DuplicateOf"/>
/// is directional (the filing case is a duplicate of the other); the rest are symmetric.
/// </summary>
public enum CaseLinkType
{
    /// <summary>Symmetric: generally related (shared indicators, actor, or context).</summary>
    RelatedTo = 0,
    /// <summary>Directional: the filing case is a duplicate of the other.</summary>
    DuplicateOf = 1,
    /// <summary>Symmetric: both cases are part of the same campaign / attack wave.</summary>
    PartOfCampaign = 2
}
