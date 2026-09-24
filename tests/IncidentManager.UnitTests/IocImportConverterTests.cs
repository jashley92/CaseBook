using FluentAssertions;
using IncidentManager.Application.Export;
using IncidentManager.Application.Import;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>PROD-06: STIX 2.1 bundle / IOC CSV → an entities-only case-import document.</summary>
public class IocImportConverterTests
{
    private const string Bundle = """
    {
      "type": "bundle", "id": "bundle--1",
      "objects": [
        { "type": "identity", "spec_version": "2.1", "id": "identity--1", "name": "Partner ISAC" },
        { "type": "ipv4-addr", "spec_version": "2.1", "id": "ipv4-addr--1", "value": "203.0.113.66",
          "x_casebook_entity_type": "IpAddress", "x_casebook_disposition": "Malicious", "x_casebook_label": "C2" },
        { "type": "x-casebook-artifact", "spec_version": "2.1", "id": "x-casebook-artifact--1", "value": "FIN-WKS-07",
          "x_casebook_entity_type": "Host", "x_casebook_disposition": "Compromised" },
        { "type": "file", "spec_version": "2.1", "id": "file--1",
          "hashes": { "MD5": "44d88612fea8a8f36de82e1278abb02f", "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" } },
        { "type": "indicator", "spec_version": "2.1", "id": "indicator--1", "name": "Phish kit host",
          "pattern": "[domain-name:value = 'login-contoso.example'] OR [url:value = 'https://login-contoso.example/o365']",
          "pattern_type": "stix" },
        { "type": "indicator", "spec_version": "2.1", "id": "indicator--2",
          "pattern": "[network-traffic:dst_port > 1024]", "pattern_type": "stix" },
        { "type": "relationship", "spec_version": "2.1", "id": "relationship--1" },
        { "type": "malware", "spec_version": "2.1", "id": "malware--1", "name": "Qakbot" }
      ]
    }
    """;

    [Fact]
    public void A_stix_bundle_becomes_entities_with_round_trip_fields_and_indicator_verdicts()
    {
        var r = IocImportConverter.Convert(Bundle);

        r.Ok.Should().BeTrue();
        r.Format.Should().Be(ImportSourceFormat.StixBundle);
        r.Document!.Origin.Should().Be("STIX 2.1 bundle (Partner ISAC)");
        r.Document.Format.Should().Be(CaseImportJson.FormatTag);
        r.Document.Entities!.Select(e => (e.Type, e.Value, e.Disposition)).Should().Equal(
            ("IpAddress", "203.0.113.66", "Malicious"),
            ("Host", "FIN-WKS-07", "Compromised"),
            ("FileHash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", null),
            ("Domain", "login-contoso.example", "Malicious"),
            ("Url", "https://login-contoso.example/o365", "Malicious"));
        r.Document.Entities[0].Label.Should().Be("C2");
        r.Document.Entities[3].Label.Should().Be("Phish kit host");

        r.Notes.Should().Contain(n => n.Contains("1 STIX indicator pattern"));
        r.Notes.Should().Contain(n => n.Contains("1 × malware") && n.Contains("1 × relationship"));
    }

    [Fact]
    public void Our_own_ioc_feed_csv_round_trips()
    {
        var feed = IocFeedCsv.Build(
        [
            new IocFeedRow(EntityType.IpAddress, "=cmd|' /C calc'!A0", DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, ["2026-01"], ["EDR"]),
            new IocFeedRow(EntityType.Domain, "evil.example", DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, ["2026-01", "2026-02"], []),
            new IocFeedRow(EntityType.FileHash, "44d88612fea8a8f36de82e1278abb02f", DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, ["2026-02"], []),
        ], DateTimeOffset.UnixEpoch);

        var r = IocImportConverter.Convert(feed, "iocs.csv");

        r.Ok.Should().BeTrue();
        r.Format.Should().Be(ImportSourceFormat.IocCsv);
        r.Document!.Origin.Should().Be("IOC CSV (iocs.csv)");
        r.Document.Entities!.Select(e => (e.Type, e.Value, e.Disposition)).Should().Equal(
            ("IpAddress", "=cmd|' /C calc'!A0", "Malicious"),   // the export's formula guard is undone
            ("Domain", "evil.example", "Malicious"),
            ("FileHash", "44d88612fea8a8f36de82e1278abb02f", "Malicious"));
        r.Document.Entities[0].Source.Should().Be("EDR");
    }

    [Fact]
    public void A_vendor_csv_with_quoted_fields_and_unknown_types_still_imports()
    {
        const string csv = "Indicator,Type,Verdict,Comment\r\n" +
                           "\"198.51.100.7\",ipv4,bad,\"seen in \"\"wave 2\"\", multi-line\nnote\"\r\n" +
                           "phish.example,widget,suspect,\r\n" +
                           ",domain,bad,blank value skipped\r\n";

        var r = IocImportConverter.Convert(csv);

        r.Document!.Entities!.Select(e => (e.Type, e.Value, e.Disposition)).Should().Equal(
            ("IpAddress", "198.51.100.7", "Malicious"),
            (null, "phish.example", "Suspicious"));
        r.Document.Entities[0].Description.Should().Be("seen in \"wave 2\", multi-line\nnote");
        r.Notes.Should().Contain(n => n.Contains("1 row(s) had a type"));
    }

    [Fact]
    public void A_headerless_list_reads_the_first_column()
    {
        var r = IocImportConverter.Convert("# partner list\n1.2.3.4\nhxxp://bad[.]site/x\n");

        r.Document!.Entities!.Select(e => e.Value).Should().Equal("1.2.3.4", "hxxp://bad[.]site/x");
        r.Notes.Should().Contain(n => n.Contains("No header row"));
    }

    [Fact]
    public void A_casebook_import_document_passes_through_and_bad_input_is_a_friendly_error()
    {
        IocImportConverter.Convert("""{ "format": "casebook-case-import", "schemaVersion": 1, "entities": [ { "value": "1.2.3.4" } ] }""")
            .Should().Match<IocImportConversion>(r => r.Ok && r.Format == ImportSourceFormat.CaseImport);
        IocImportConverter.Convert("{ not json").Error.Should().Contain("valid JSON");
        IocImportConverter.Convert("""{ "type": "bundle", "objects": [ { "type": "malware" } ] }""").Error
            .Should().Contain("no indicators");
        IocImportConverter.Convert("  ").Ok.Should().BeFalse();
    }

    [Fact]
    public void Pattern_reader_handles_hashes_escapes_and_ignores_non_equality()
    {
        IocImportConverter.PatternObservables("[file:hashes.'SHA-256' = 'abc'] AND [email-addr:value = 'o\\'brien@x.example']")
            .Should().Equal((EntityType.FileHash, "abc"), (EntityType.EmailAddress, "o'brien@x.example"));
        IocImportConverter.PatternObservables("[ipv4-addr:value ISSUBSET '10.0.0.0/8']").Should().BeEmpty();
    }
}
