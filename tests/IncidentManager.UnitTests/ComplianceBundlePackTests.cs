using System.IO.Compression;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Compliance;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// The compliance-bundle packaging (C-01): the zip carries the expected files, the manifest reflects the
/// verification outcome, and the CSVs escape their fields — so the artifact stands on its own for an examiner.
/// </summary>
public class ComplianceBundlePackTests
{
    private static ComplianceBundleModel Model(ChainVerificationResult chainResult, params SealLine[] seals)
    {
        var segment = new List<AuditLogEntry>
        {
            new() { Sequence = 5, AtUtc = DateTimeOffset.UnixEpoch, Actor = "analyst1",
                    Action = AuditAction.Create, EntityType = "Case", EntityId = "abc",
                    CaseNumber = "2026-01_Test", Summary = "Create Case", PrevHash = "aa", EntryHash = "bb" },
            // A summary with a comma and quote to exercise RFC-4180 escaping.
            new() { Sequence = 6, AtUtc = DateTimeOffset.UnixEpoch, Actor = "analyst1",
                    Action = AuditAction.Update, EntityType = "Case", EntityId = "abc",
                    CaseNumber = "2026-01_Test", Summary = "Changed \"severity\", again", PrevHash = "bb", EntryHash = "cc" },
        };
        return new ComplianceBundleModel(
            GeneratedAtUtc: DateTimeOffset.UnixEpoch,
            GeneratedByDisplay: "Dev Analyst",
            GeneratedByUserId: "S-1-5-21-DEV-1001",
            FromUtc: DateTimeOffset.UnixEpoch,
            ToUtc: DateTimeOffset.UnixEpoch.AddDays(1),
            Segment: segment,
            TotalChainLength: 6,
            SegmentFirstSequence: 5,
            SegmentLastSequence: 6,
            ChainResult: chainResult,
            ChainHeadSequence: 6,
            ChainHeadHash: "cc",
            Seals: seals,
            CoveringSeal: seals.Length > 0 ? seals[0] : null,
            Algorithm: "RSASSA-PKCS1-v1_5-SHA256",
            KeyId: "deadbeef",
            PublicKeyPem: "-----BEGIN PUBLIC KEY-----\nMII...\n-----END PUBLIC KEY-----\n");
    }

    private static SealLine Seal() => new(
        new IntegritySeal { UpToSequence = 6, SealedAtUtc = DateTimeOffset.UnixEpoch, SealedBy = "admin1",
            Algorithm = "RSASSA-PKCS1-v1_5-SHA256", KeyId = "deadbeef", ChainHeadHash = "cc", Signature = "sig==" },
        SignatureValid: true, ChainMatches: true);

    private static Dictionary<string, string> Unzip(byte[] bytes)
    {
        using var archive = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
        return archive.Entries.ToDictionary(e => e.Name, e =>
        {
            using var reader = new StreamReader(e.Open(), Encoding.UTF8);
            return reader.ReadToEnd();
        });
    }

    [Fact]
    public void Zip_contains_the_expected_files()
    {
        var files = Unzip(ComplianceBundlePack.Zip(Model(ChainVerificationResult.Valid, Seal())));

        files.Keys.Should().BeEquivalentTo(
            "manifest.txt", "audit-chain.csv", "seals.csv", "signing-public-key.pem", "VERIFY.txt");
        files["signing-public-key.pem"].Should().Contain("BEGIN PUBLIC KEY");
    }

    [Fact]
    public void Manifest_reports_a_valid_chain_and_an_authentic_covering_seal()
    {
        var files = Unzip(ComplianceBundlePack.Zip(Model(ChainVerificationResult.Valid, Seal())));
        var manifest = files["manifest.txt"];

        manifest.Should().Contain("Whole-chain verification : VALID");
        manifest.Should().Contain("Sequence span      : #5 through #6");
        manifest.Should().Contain("Entries in range   : 2");
        manifest.Should().Contain("signature AUTHENTIC, history UNCHANGED");
    }

    [Fact]
    public void Manifest_reports_a_broken_chain()
    {
        var broken = ChainVerificationResult.Broken(6, "Entry hash does not match its content.");
        var manifest = Unzip(ComplianceBundlePack.Zip(Model(broken)))["manifest.txt"];

        manifest.Should().Contain("Whole-chain verification : BROKEN at sequence #6");
        manifest.Should().Contain("Entry hash does not match its content.");
        manifest.Should().Contain("Covering seal     : NONE");
    }

    [Fact]
    public void Audit_csv_has_a_header_a_row_per_entry_and_rfc4180_escaping()
    {
        var csv = Unzip(ComplianceBundlePack.Zip(Model(ChainVerificationResult.Valid, Seal())))["audit-chain.csv"];
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        lines[0].Should().StartWith("Sequence,AtUtc,Actor,Action,EntityType,EntityId,CaseNumber,Summary");
        lines.Should().HaveCount(3); // header + 2 entries
        // The comma/quote-bearing summary is quoted with the embedded quotes doubled.
        csv.Should().Contain("\"Changed \"\"severity\"\", again\"");
    }
}
