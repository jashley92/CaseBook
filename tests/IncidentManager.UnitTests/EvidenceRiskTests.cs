using FluentAssertions;
using IncidentManager.Application.Evidence;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// PROD-58: which evidence counts as able to run (and so downloads first inside a zip with the password "infected"), by
/// name, type and first bytes; the setting's three modes; and the name inside the zip, which can never point an unzip
/// tool outside the folder it extracts to.
/// </summary>
public sealed class EvidenceRiskTests
{
    [Theory]
    [InlineData("invoice.exe", null)]
    [InlineData("INVOICE.EXE", "")]
    [InlineData("loader.ps1", "text/plain")]
    [InlineData("macro.xlsm", null)]
    [InlineData("payload.lnk", null)]
    [InlineData("disk.iso", null)]
    [InlineData("phish.html", null)]
    [InlineData("logo.svg", null)]
    [InlineData("Q3.docx", "application/vnd.ms-word.document.macroEnabled.12")]
    [InlineData("noext", "application/x-msdownload")]
    [InlineData("readme.txt", "text/html; charset=utf-8")]
    public void Programs_scripts_macros_and_pages_are_risky(string name, string? type) =>
        EvidenceRisk.IsRisky(name, type).Should().BeTrue();

    [Theory]
    [InlineData("export.csv", "text/csv")]
    [InlineData("screenshot.png", "image/png")]
    [InlineData("report.pdf", "application/pdf")]
    [InlineData("notes.txt", "text/plain")]
    [InlineData("capture.pcap", "application/octet-stream")]
    [InlineData("memory.dmp", "")]
    [InlineData("evidence.bin", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void Ordinary_files_are_not(string? name, string? type) => EvidenceRisk.IsRisky(name, type).Should().BeFalse();

    public static TheoryData<byte[], string> Headers => new()
    {
        { "MZ\x90\0"u8.ToArray(), "Windows program" },
        { [0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1], "Linux program" },
        { [0xCF, 0xFA, 0xED, 0xFE, 7, 0], "macOS program" },
        { [0xCA, 0xFE, 0xBA, 0xBE, 0, 0], "macOS program" },
        { [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], "legacy Office or Outlook" },
    };

    [Theory]
    [MemberData(nameof(Headers))]
    public void A_renamed_program_is_caught_by_its_first_bytes(byte[] header, string what)
    {
        EvidenceRisk.Reason("holiday-photo.jpg", "image/jpeg", header).Should().Contain(what);
        EvidenceRisk.IsRisky("holiday-photo.jpg", "image/jpeg").Should().BeFalse("by name and type alone it looks harmless");
    }

    [Fact]
    public void The_setting_decides_which_files_zip_first_and_reads_only_its_names()
    {
        EvidenceRisk.ZipFirst(SafeDownloadMode.RiskyTypes, "a.exe", null).Should().BeTrue();
        EvidenceRisk.ZipFirst(SafeDownloadMode.RiskyTypes, "a.csv", null).Should().BeFalse();
        EvidenceRisk.ZipFirst(SafeDownloadMode.Always, "a.csv", null).Should().BeTrue();
        EvidenceRisk.ZipFirst(SafeDownloadMode.Off, "a.exe", null).Should().BeFalse();

        new EvidenceStorageOptions { SafeDownload = "always" }.SafeDownloadMode.Should().Be(SafeDownloadMode.Always);
        new EvidenceStorageOptions { SafeDownload = " Off " }.SafeDownloadMode.Should().Be(SafeDownloadMode.Off);
        new EvidenceStorageOptions { SafeDownload = "2" }.SafeDownloadMode.Should().Be(SafeDownloadMode.RiskyTypes, "a number isn't a name (C16)");
        new EvidenceStorageOptions { SafeDownload = "Sometimes" }.SafeDownloadMode.Should().Be(SafeDownloadMode.RiskyTypes);
        new EvidenceStorageOptions().SafeDownloadMode.Should().Be(SafeDownloadMode.RiskyTypes);
    }

    [Theory]
    [InlineData("invoice.exe", "invoice.exe")]
    [InlineData(@"..\..\Windows\System32\evil.dll", "evil.dll")]
    [InlineData("../../etc/cron.d/job", "job")]
    [InlineData("C:\\temp\\a:b?.exe", "ab.exe")]
    [InlineData("tab\there\nnew.txt", "tabherenew.txt")]
    [InlineData("...", "evidence.bin")]
    [InlineData("", "evidence.bin")]
    [InlineData(null, "evidence.bin")]
    [InlineData("name. ", "name")]
    public void The_name_inside_the_zip_is_the_files_own_name_and_nothing_else(string? original, string expected) =>
        EvidenceRisk.EntryName(original).Should().Be(expected);

    [Fact]
    public void A_very_long_name_is_kept_short() =>
        EvidenceRisk.EntryName(new string('a', 400) + ".exe").Length.Should().Be(200);
}
