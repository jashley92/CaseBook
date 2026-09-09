using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Siem;
using Xunit;

namespace IncidentManager.UnitTests;

public class SecurityEventJsonTests
{
    [Fact]
    public void Serializes_stable_camelCase_fields_with_string_enums_and_omits_nulls()
    {
        var e = new SecurityEvent
        {
            EventId = SecurityEventIds.CaseOpened,
            Category = "DataAccess",
            Action = "CaseOpen",
            Outcome = SecurityOutcome.Success,
            Severity = SecuritySeverity.Info,
            Actor = "analyst1",
            CaseNumber = "2026-01_Alpha",
            TargetType = "Case",
            AtUtc = new DateTimeOffset(2026, 8, 24, 12, 0, 0, TimeSpan.Zero),
            Host = "SOC-APP-01"
            // ActorUpn / TargetId / Detail left null → must be omitted
        };

        using var doc = JsonDocument.Parse(SecurityEventJson.Serialize(e));
        var root = doc.RootElement;

        root.GetProperty("eventId").GetInt32().Should().Be(5301);
        root.GetProperty("category").GetString().Should().Be("DataAccess");
        root.GetProperty("action").GetString().Should().Be("CaseOpen");
        root.GetProperty("outcome").GetString().Should().Be("Success");   // enum as name, not 0
        root.GetProperty("severity").GetString().Should().Be("Info");
        root.GetProperty("actor").GetString().Should().Be("analyst1");
        root.GetProperty("caseNumber").GetString().Should().Be("2026-01_Alpha");
        root.GetProperty("host").GetString().Should().Be("SOC-APP-01");
        root.GetProperty("app").GetString().Should().Be("CaseBook");

        root.TryGetProperty("actorUpn", out _).Should().BeFalse(); // nulls omitted
        root.TryGetProperty("targetId", out _).Should().BeFalse();
        root.TryGetProperty("detail", out _).Should().BeFalse();
    }
}

public class SecurityEventCefTests
{
    private static SecurityEvent Restricted() => new()
    {
        EventId = SecurityEventIds.RestrictedCaseAccessed, Category = "DataAccess", Action = "CaseOpen",
        Outcome = SecurityOutcome.Success, Severity = SecuritySeverity.High, Actor = "analyst1",
        CaseNumber = "2026-01_Alpha", TargetType = "Case",
        AtUtc = new DateTimeOffset(2026, 8, 24, 12, 0, 0, TimeSpan.Zero), Host = "SOC-APP-01"
    };

    [Fact]
    public void Formats_cef_header_and_extension_fields()
    {
        var cef = SecurityEventCef.ToCef(Restricted());
        cef.Should().StartWith("CEF:0|CaseBook|CaseBook|");
        cef.Should().Contain("|5305|CaseOpen|8|"); // classId | name | CEF severity (High => 8)
        cef.Should().Contain("suser=analyst1");
        cef.Should().Contain("cat=DataAccess");
        cef.Should().Contain("act=CaseOpen");
        cef.Should().Contain("cs1Label=caseNumber");
        cef.Should().Contain("cs1=2026-01_Alpha");
        cef.Should().Contain("dvchost=SOC-APP-01");
    }

    [Fact]
    public void Wraps_cef_in_an_rfc5424_syslog_line_with_priority()
    {
        var e = new SecurityEvent
        {
            EventId = SecurityEventIds.AuditChainBroken, Category = "Integrity", Action = "AuditChainBroken",
            Severity = SecuritySeverity.Critical, Actor = "system",
            AtUtc = new DateTimeOffset(2026, 8, 24, 12, 0, 0, TimeSpan.Zero), Host = "H"
        };
        // Critical => syslog severity 2; facility 16 (local0) => PRI = 16*8 + 2 = 130.
        SecurityEventCef.ToSyslogLine(e, facility: 16, appName: "CaseBook")
            .Should().StartWith("<130>1 2026-08-24T12:00:00.000Z H CaseBook - - - CEF:0|");
    }

    [Fact]
    public void Escapes_pipe_in_header_and_equals_in_extension()
    {
        var e = new SecurityEvent
        {
            EventId = 5304, Category = "DataAccess", Action = "Ex|port", Actor = "a", Detail = "k=v",
            AtUtc = DateTimeOffset.UnixEpoch, Host = "H"
        };
        var cef = SecurityEventCef.ToCef(e);
        cef.Should().Contain("Ex\\|port"); // pipe escaped in the Name header field
        cef.Should().Contain("msg=k\\=v"); // equals escaped in an extension value
    }
}

public class SecurityEventIdsTests
{
    [Fact]
    public void Catalog_ids_are_the_stable_contract_values()
    {
        SecurityEventIds.AuditChainBroken.Should().Be(5001);
        SecurityEventIds.AuthenticationFailed.Should().Be(5101);
        SecurityEventIds.AuthorizationDenied.Should().Be(5201);
        SecurityEventIds.CaseOpened.Should().Be(5301);
        SecurityEventIds.EvidenceDownloaded.Should().Be(5302);
        SecurityEventIds.ReportDownloaded.Should().Be(5303);
        SecurityEventIds.DataExported.Should().Be(5304);
        SecurityEventIds.RestrictedCaseAccessed.Should().Be(5305);
        SecurityEventIds.RoleChanged.Should().Be(5401);
        SecurityEventIds.AdGroupMappingChanged.Should().Be(5402);
        SecurityEventIds.SettingChanged.Should().Be(5403);
        SecurityEventIds.LegalHoldPlaced.Should().Be(5501);
        SecurityEventIds.LegalHoldReleased.Should().Be(5502);
        SecurityEventIds.BreachEscalated.Should().Be(5503);
    }

    [Theory]
    [InlineData(AccessType.CaseOpen, false, 5301)]
    [InlineData(AccessType.CaseOpen, true, 5305)]   // restricted read gets its own id
    [InlineData(AccessType.EvidenceDownload, false, 5302)]
    [InlineData(AccessType.ReportDownload, false, 5303)]
    [InlineData(AccessType.Export, false, 5304)]
    public void CaseAccess_maps_type_and_restricted_to_the_right_id(AccessType type, bool restricted, int expectedId)
    {
        var e = SecurityEvents.CaseAccess(type, restricted, "analyst1", null, "2026-01_Alpha", null, null);
        e.EventId.Should().Be(expectedId);
        e.Category.Should().Be("DataAccess");
    }
}
