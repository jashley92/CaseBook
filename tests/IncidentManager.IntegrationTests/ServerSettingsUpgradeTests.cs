using System.Text.Json;
using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Infrastructure.Secrets;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Web.Siem;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// The upgrade adds the server-side settings an older appsettings.Production.json lacks (deploy\lib\CaseBookSettings.ps1),
/// copying each from the release's appsettings.json, so an administrator can find and set them. That only changes nothing
/// if the release's appsettings.json holds each of them at the value the app uses without it, and none of them is an
/// in-app setting (set in the file, it would sit beside the form's value and confuse which one counts).
/// </summary>
public sealed partial class ServerSettingsUpgradeTests
{
    private static readonly string Root = RepoRoot();
    private static readonly string BasePath = Path.Combine(Root, "src", "IncidentManager.Web", "appsettings.json");
    private static readonly string TemplatePath = Path.Combine(Root, "deploy", "appsettings.Production.template.json");

    [Fact]
    public void Every_setting_the_upgrade_adds_is_in_the_release_settings_and_the_install_template()
    {
        var baseJson = JsonDocument.Parse(File.ReadAllText(BasePath));
        var template = JsonDocument.Parse(File.ReadAllText(TemplatePath));
        var paths = ListedIn("Get-CaseBookServerSettingPaths");
        paths.Should().Contain("Storage:Encryption", "the evidence key settings are the reason this exists");

        foreach (var path in paths)
        {
            Find(baseJson.RootElement, path).Should().NotBeNull($"{path} is copied from the release's appsettings.json");
            Find(template.RootElement, path).Should().NotBeNull($"{path} is in a fresh install's settings too");
        }
        foreach (var path in ListedIn("Get-CaseBookServerSettingExclusions"))
            Find(baseJson.RootElement, path).Should().NotBeNull($"{path} is left out, so it must be one the upgrade would copy");
    }

    [Fact]
    public void None_of_them_is_an_in_app_setting()
    {
        var paths = ListedIn("Get-CaseBookServerSettingPaths");
        var inApp = SettingsCatalog.Editable.Select(d => d.Key)
            .Where(k => paths.Any(p => k.Equals(p, StringComparison.OrdinalIgnoreCase) || k.StartsWith(p + ":", StringComparison.OrdinalIgnoreCase)));
        inApp.Should().BeEmpty("an in-app setting is set in Administration, not in appsettings.Production.json");
    }

    [Fact]
    public void The_release_settings_hold_the_values_the_app_uses_without_them()
    {
        var config = new ConfigurationBuilder().AddJsonFile(BasePath).Build();

        config.GetSection("Storage:Encryption").Get<EvidenceEncryptionOptions>().Should().BeEquivalentTo(new EvidenceEncryptionOptions());
        var integrity = new SealSigningOptions();
        config.GetSection("Integrity").Bind(integrity);
        integrity.SigningKey.Should().BeEquivalentTo(new SigningKeyOptions());
        integrity.ChainKey.Should().BeEquivalentTo(new ChainKeyOptions());
        integrity.RetiredPublicKeysPath.Should().Be(new SealSigningOptions().RetiredPublicKeysPath);
        config.GetSection("Integrity:SealCopies").Get<SealCopyOptions>().Should().BeEquivalentTo(new SealCopyOptions());
        config.GetSection("Siem:EventLog").Get<SiemEventLogOptions>().Should().BeEquivalentTo(new SiemEventLogOptions());
        config.GetSection("Secrets:CyberArk").Get<CyberArkOptions>().Should().BeEquivalentTo(new CyberArkOptions());
        config[TrustedBundleKeys.SettingKey].Should().BeNullOrWhiteSpace("blank means no trusted keys");
    }

    [Fact]
    public void The_install_template_is_plain_ascii()
    {
        // Install-CaseBook.ps1 reads it with Windows PowerShell 5.1's Get-Content, which decodes a BOM-less file as ANSI.
        File.ReadAllBytes(TemplatePath).Should().OnlyContain(b => b < 128);
    }

    [Fact]
    public void The_upgrade_checks_before_the_backup_and_adds_after_it()
    {
        var upgrade = File.ReadAllText(Path.Combine(Root, "deploy", "Upgrade-CaseBook.ps1"));
        var found = upgrade.IndexOf("Find-CaseBookMissingServerSettings", StringComparison.Ordinal);
        var backup = upgrade.IndexOf("Copy-Item $prodSettings (Join-Path $BackupRoot", StringComparison.Ordinal);
        var added = upgrade.IndexOf("Add-CaseBookServerSettings $liveCfg", StringComparison.Ordinal);   // the preflight tries it on a copy
        upgrade.Should().Contain(@"lib\CaseBookSettings.ps1");
        found.Should().BeGreaterThan(-1);
        backup.Should().BeGreaterThan(found, "the preflight says what will be added");
        added.Should().BeGreaterThan(backup, "the settings file is backed up before it's changed");
    }

    private static List<string> ListedIn(string function)
    {
        var lib = File.ReadAllText(Path.Combine(Root, "deploy", "lib", "CaseBookSettings.ps1"));
        var body = Regex.Match(lib, @"function\s+" + Regex.Escape(function) + @"\s*\{\s*return\s+@\(([^)]*)\)", RegexOptions.None, TimeSpan.FromSeconds(1));
        body.Success.Should().BeTrue($"{function} returns its list as @(...)");
        return Quoted().Matches(body.Groups[1].Value).Select(m => m.Groups[1].Value).ToList();
    }

    private static JsonElement? Find(JsonElement node, string path)
    {
        foreach (var part in path.Split(':'))
        {
            if (node.ValueKind != JsonValueKind.Object) return null;
            var match = node.EnumerateObject().Where(p => p.Name.Equals(part, StringComparison.OrdinalIgnoreCase)).Select(p => (JsonElement?)p.Value).FirstOrDefault();
            if (match is null) return null;
            node = match.Value;
        }
        return node;
    }

    [GeneratedRegex("'([^']+)'", RegexOptions.None, 1000)]
    private static partial Regex Quoted();

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) dir = dir.Parent;
        return dir!.FullName;
    }
}
