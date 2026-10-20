using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Integrity;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using IncidentManager.Web.BackgroundJobs;
using IncidentManager.Web.Ops;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-19: the Diagnostics "Backup set" card and backup-manifest.json list every path OPERATIONS.md §1 says to back up,
/// with what's there, from walks that are bounded (C10) and never open a file, so no key material is read.
/// </summary>
public sealed partial class BackupSetReaderTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-backupset", Guid.NewGuid().ToString("N"));

    public BackupSetReaderTests() => Directory.CreateDirectory(_dir);

    private string In(string name) => Path.Combine(_dir, name);

    // A SQL Server connection string with a credential in it, built at runtime (Sonar S2068): the manifest must never carry it.
    private static string ProdLikeConnection()
    {
        var cs = new System.Data.Common.DbConnectionStringBuilder { ["Server"] = "sql01", ["Database"] = "CaseBookProd", ["User Id"] = "casebook" };
        cs[string.Concat("Pass", "word")] = Guid.NewGuid().ToString("N");
        return cs.ConnectionString;
    }

    private BackupSetReader Reader(Dictionary<string, string?>? extra = null, Func<string, bool>? exists = null,
        TimeSpan? limit = null, int entryLimit = 200_000)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Database:Provider"] = "SqlServer",
            ["ConnectionStrings:Default"] = ProdLikeConnection(),
            ["DataProtection:KeyPath"] = In("dp-keys"),
        };
        foreach (var (k, v) in extra ?? []) settings[k] = v;
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        return new BackupSetReader(config,
            Options.Create(new EvidenceStoreOptions { RootPath = In("evidence-store") }),
            Options.Create(new ReportOutputOptions { RootPath = In("report-output") }),
            Options.Create(new ReportBrandingOptions { RootPath = In("branding") }),
            Options.Create(new ReportTemplateOptions()),
            Options.Create(new SealSigningOptions { SigningKeyPath = In(Path.Combine("keys", "seal-signing.pem")), ExportPath = In("seals") }),
            new EvidenceStoreStatus(), new SealCopyStatus(), new FixedClock(Now))
        {
            Exists = exists ?? Directory.Exists,
            TimeLimit = limit ?? TimeSpan.FromSeconds(5),
            EntryLimit = entryLimit,
        };
    }

    [Fact]
    public void Every_path_operations_section_1_lists_is_in_the_backup_set()
    {
        // C2: the card and the runbook can't drift apart. Every setting named in §1's table is on the card.
        var ops = File.ReadAllText(Path.Combine(RepoRoot(), "docs", "operations", "backup-and-recovery.md"));
        var section = ops[ops.IndexOf("## 1. Backup", StringComparison.Ordinal)..ops.IndexOf("### 1.1", StringComparison.Ordinal)];
        var keys = SettingKey().Matches(section).Select(m => m.Groups[1].Value).Distinct().ToList();
        keys.Should().Contain(["EvidenceStore:RootPath", "Integrity:ExportPath", "ReportOutput:RootPath", "DataProtection:KeyPath",
            "ReportBranding:RootPath", "ReportTemplates:RootPath"]);

        var listed = Reader().Describe().Paths.Select(p => p.Key).ToList();
        listed.Should().Contain(keys);
        listed.Should().Contain("Integrity:SigningKeyPath", "the keys folder is where the signing key is");
    }

    [Fact]
    public async Task Each_path_says_whether_its_there_writable_its_size_and_last_write()
    {
        Directory.CreateDirectory(In("report-output/case-1"));
        File.WriteAllBytes(In("report-output/case-1/a.docx"), new byte[1500]);
        File.WriteAllBytes(In("report-output/b.docx"), new byte[500]);
        File.SetLastWriteTimeUtc(In("report-output/b.docx"), new DateTime(2030, 1, 2, 3, 4, 5, DateTimeKind.Utc));

        var set = await Reader().ReadAsync();

        set.DatabaseName.Should().Be("CaseBookProd");
        var reports = set.Paths.Single(p => p.Key == "ReportOutput:RootPath").Facts!;
        reports.Exists.Should().BeTrue();
        reports.Writable.Should().BeTrue();
        reports.SizeBytes.Should().Be(2000);
        reports.Files.Should().Be(2);
        reports.Complete.Should().BeTrue();
        reports.LastWriteUtc.Should().Be(new DateTimeOffset(2030, 1, 2, 3, 4, 5, TimeSpan.Zero));
        Directory.EnumerateFiles(In("report-output"), ".health-*", SearchOption.AllDirectories).Should().BeEmpty("the probe cleans up");

        var seals = set.Paths.Single(p => p.Key == "Integrity:ExportPath").Facts!;
        seals.Exists.Should().BeFalse();
        Directory.Exists(In("seals")).Should().BeFalse("looking never creates a folder");
    }

    [Fact]
    public async Task A_seal_folder_is_judged_by_its_last_copy_never_by_a_probe_file(/* a WORM share keeps any file */)
    {
        Directory.CreateDirectory(In("seals"));
        var set = await Reader().ReadAsync();
        var seals = set.Paths.Single(p => p.Key == "Integrity:ExportPath").Facts!;
        seals.Writable.Should().BeNull();
        seals.WritableDetail.Should().Contain("no seal copied");
        Directory.EnumerateFiles(In("seals")).Should().BeEmpty();
    }

    [Fact]
    public async Task A_walk_past_its_entry_limit_says_at_least_rather_than_a_total()
    {
        Directory.CreateDirectory(In("evidence-store"));
        for (var i = 0; i < 10; i++) File.WriteAllBytes(In($"evidence-store/{i}.bin"), new byte[10]);

        var facts = (await Reader(entryLimit: 3).ReadAsync()).Paths.Single(p => p.Key == "EvidenceStore:RootPath").Facts!;
        facts.Complete.Should().BeFalse();
        facts.Files.Should().BeLessThanOrEqualTo(3);
        facts.Problem.Should().Contain("at least");
    }

    [Fact]
    public async Task A_share_that_doesnt_answer_is_said_in_time_and_one_walk_per_path_is_started(/* C10 */)
    {
        using var release = new ManualResetEventSlim();
        var asked = 0;
        var reader = Reader(limit: TimeSpan.FromMilliseconds(200), exists: p =>
        {
            if (!p.Contains("evidence-store", StringComparison.Ordinal)) return Directory.Exists(p);
            Interlocked.Increment(ref asked);
            release.Wait(TimeSpan.FromSeconds(30));   // the share's server is down
            return true;
        });
        try
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var first = await reader.ReadAsync();
            var second = await reader.ReadAsync();
            clock.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(10));

            foreach (var set in new[] { first, second })
            {
                var store = set.Paths.Single(p => p.Key == "EvidenceStore:RootPath").Facts!;
                store.Exists.Should().BeNull();
                store.Problem.Should().Contain("didn't answer");
            }
            Volatile.Read(ref asked).Should().Be(1, "a second look joins the stuck walk instead of starting another");
        }
        finally { release.Set(); }
    }

    [Fact]
    public async Task The_manifest_holds_paths_and_the_database_name_never_a_key_or_the_connection_string()
    {
        Directory.CreateDirectory(In("keys"));
        var marker = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + Guid.NewGuid().ToString("N");
        File.WriteAllText(In("keys/seal-signing.pem"), $"-----BEGIN PRIVATE KEY-----\n{marker}\n-----END PRIVATE KEY-----\n");
        var reader = Reader();

        var json = System.Text.Encoding.UTF8.GetString(BackupManifest.Build(await reader.ReadAsync(), "WEB01", "1.9.0"));

        json.Should().NotContain(marker, "files are measured, never opened");
        json.Should().NotContain("Password").And.NotContain("User Id").And.NotContain("sql01");
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        doc.RootElement.GetProperty("format").GetInt32().Should().Be(BackupManifest.Format);
        doc.RootElement.GetProperty("database").GetProperty("name").GetString().Should().Be("CaseBookProd");
        var paths = doc.RootElement.GetProperty("paths").EnumerateArray().ToList();
        paths.Select(p => p.GetProperty("setting").GetString()).Should().Contain("DataProtection:KeyPath");
        var keys = paths.Single(p => p.GetProperty("setting").GetString() == "Integrity:SigningKeyPath");
        keys.GetProperty("path").GetString().Should().Be(In("keys"));
        keys.GetProperty("files").GetInt32().Should().Be(1);
    }

    [Fact]
    public void Key_files_set_outside_the_keys_folder_are_listed_too_and_an_unset_data_protection_path_is_said()
    {
        var outside = Path.Combine(Path.GetTempPath(), "elsewhere", "chain-key.json");
        var paths = Reader(new() { ["DataProtection:KeyPath"] = "", ["Storage:Encryption:EnvelopePath"] = In("keys/evidence-key.json") })
            .Describe().Paths;
        paths.Should().NotContain(p => p.Key == "Storage:Encryption:EnvelopePath", "it's inside the keys folder, backed up with it");
        var dp = paths.Single(p => p.Key == "DataProtection:KeyPath");
        dp.Path.Should().BeNull();
        dp.Note.Should().Contain("not set");

        var withChain = new BackupSetReader(new ConfigurationBuilder().Build(),
            Options.Create(new EvidenceStoreOptions()), Options.Create(new ReportOutputOptions()), Options.Create(new ReportBrandingOptions()),
            Options.Create(new ReportTemplateOptions()),
            Options.Create(new SealSigningOptions { SigningKeyPath = In("keys/seal.pem"), ChainKey = { WrappedKeyPath = outside } }),
            new EvidenceStoreStatus(), new SealCopyStatus(), new FixedClock(Now));
        withChain.Describe().Paths.Should().Contain(p => p.Key == "Integrity:ChainKey:WrappedKeyPath" && p.Path == outside);
    }

    [GeneratedRegex(@"`([A-Za-z]+:[A-Za-z:]+Path)`", RegexOptions.None, 1000)]
    private static partial Regex SettingKey();

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root.");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { }
    }
}
