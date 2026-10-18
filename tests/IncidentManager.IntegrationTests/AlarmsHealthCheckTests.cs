using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Ops;
using IncidentManager.Web.HealthChecks;
using IncidentManager.Web.Ops;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.FileProviders;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-18: /health/alarms says Degraded while any alarm the app raises in banners and the SIEM is up (a broken chain,
/// evidence drift, an unavailable evidence key, a failing seal copy, a stale or missing backup) and Healthy otherwise.
/// The reasons stay in the description, which the endpoint never writes.
/// </summary>
public sealed class AlarmsHealthCheckTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-alarms", Guid.NewGuid().ToString("N"));
    private readonly IntegrityMonitor _integrity = new();
    private readonly EvidenceIntegrityMonitor _evidence = new();
    private readonly Keys _keys = new();
    private readonly SealCopyStatus _seals = new();

    public AlarmsHealthCheckTests() => Directory.CreateDirectory(_dir);

    private sealed class Keys : IEvidenceKeyring
    {
        public EvidenceKeyState State { get; set; } = EvidenceKeyState.Ready;
        public string? CurrentKeyId => "k1";
        public byte[]? Key(string keyId) => null;
        public string? Problem => null;
    }

    private sealed class Env(string root) : IWebHostEnvironment
    {
        public string WebRootPath { get; set; } = root;
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string ApplicationName { get; set; } = "CaseBook";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = root;
        public string EnvironmentName { get; set; } = "Production";
    }

    /// <summary>The backup reader, with a status file written as the backup job would (null: none configured).</summary>
    private BackupHealthReader Backup(DateTimeOffset? lastBackup, bool configured = true)
    {
        var settings = new Dictionary<string, string?>();
        if (configured)
        {
            var file = Path.Combine(_dir, "backup-status.json");
            File.WriteAllText(file, System.Text.Json.JsonSerializer.Serialize(new BackupStatusFile
            {
                LastBackupUtc = lastBackup, LastVerifiedRestoreUtc = Now.AddDays(-1),
            }));
            settings["BackupStatus:FilePath"] = file;
        }
        return new BackupHealthReader(new ConfigurationBuilder().AddInMemoryCollection(settings).Build(), new Env(_dir), new FixedClock(Now));
    }

    private AlarmsHealthCheck Check(BackupHealthReader? backup = null) =>
        new(_integrity, _evidence, _keys, _seals, backup ?? Backup(Now.AddHours(-1)));

    private static Task<HealthCheckResult> Run(AlarmsHealthCheck check) => check.CheckHealthAsync(new HealthCheckContext());

    [Fact]
    public async Task With_no_alarm_up_it_is_healthy()
    {
        _integrity.RecordResult(new ChainVerificationResult(true, null, null), Now);
        _evidence.RecordResult(new EvidenceVerificationResult(3, [], Now), Now);
        _seals.Record("export folder", Now, null);

        (await Run(Check())).Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public async Task Nothing_checked_yet_and_backups_not_configured_are_not_alarms()
    {
        (await Run(Check(Backup(null, configured: false)))).Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public async Task A_broken_audit_chain_is_degraded_until_it_verifies_again()
    {
        _integrity.RecordResult(new ChainVerificationResult(false, 42, "row hash mismatch"), Now);
        var broken = await Run(Check());
        broken.Status.Should().Be(HealthStatus.Degraded);
        broken.Description.Should().Contain("audit chain");

        _integrity.RecordResult(new ChainVerificationResult(true, null, null), Now);
        (await Run(Check())).Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public async Task Evidence_drift_is_degraded()
    {
        var drift = new EvidenceDrift(Guid.NewGuid(), Guid.NewGuid(), "IRP-1", "a.png", "aa", "bb", EvidenceDriftKind.HashMismatch, "changed");
        _evidence.RecordResult(new EvidenceVerificationResult(1, [drift], Now), Now);

        var result = await Run(Check());
        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Contain("evidence drift");
    }

    [Fact]
    public async Task An_unavailable_evidence_key_is_degraded_but_one_waiting_for_a_backup_is_not()
    {
        _keys.State = EvidenceKeyState.NeedsBackup;
        (await Run(Check())).Status.Should().Be(HealthStatus.Healthy, "Diagnostics asks for the backup; nothing is failing");

        _keys.State = EvidenceKeyState.Unavailable;
        var result = await Run(Check());
        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Contain("evidence key");
    }

    [Fact]
    public async Task A_seal_copy_whose_last_attempt_failed_is_degraded_until_one_succeeds()
    {
        _seals.Record("export folder", Now, "access denied");
        var result = await Run(Check());
        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Contain("seal copy");

        _seals.Record("export folder", Now.AddMinutes(5), null);
        (await Run(Check())).Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public async Task A_stale_or_missing_backup_is_degraded()
    {
        var stale = await Run(Check(Backup(Now.AddDays(-3))));
        stale.Status.Should().Be(HealthStatus.Degraded);
        stale.Description.Should().Contain("backup stale");

        var missing = await Run(Check(Backup(null)));
        missing.Status.Should().Be(HealthStatus.Degraded);
        missing.Description.Should().Contain("backup missing");
    }

    [Fact]
    public async Task A_backup_status_file_on_a_share_that_doesnt_answer_is_degraded_in_time(/* C10 */)
    {
        using var never = new ManualResetEventSlim();
        var check = new AlarmsHealthCheck(_integrity, _evidence, _keys, _seals, Backup(Now))
        {
            TimeLimit = TimeSpan.FromMilliseconds(200),
            ReadBackup = () => { never.Wait(TimeSpan.FromSeconds(30)); throw new IOException("never"); },
        };
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var result = await Run(check);
        never.Set();

        result.Status.Should().Be(HealthStatus.Degraded);
        watch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task A_check_that_fails_is_degraded_never_unhealthy()
    {
        var check = new AlarmsHealthCheck(_integrity, _evidence, _keys, _seals, Backup(Now))
        {
            ReadBackup = () => throw new UnauthorizedAccessException("denied"),
        };
        (await Run(check)).Status.Should().Be(HealthStatus.Degraded);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { }
    }
}
