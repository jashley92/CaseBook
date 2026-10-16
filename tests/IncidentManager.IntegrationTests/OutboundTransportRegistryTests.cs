using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-576 closes the class for other hosts: every file that opens a connection to another host (SMTP, HTTP, syslog)
/// either backs a target that isn't answering off through <c>OutboundCircuit</c> (so a user action doesn't wait out a
/// stalled relay on every send) or is listed here with why it needn't. A new outbound transport must do one or the other.
/// </summary>
public sealed class OutboundTransportRegistryTests
{
    private static readonly Dictionary<string, string> NotOnTheUserPath = new(StringComparer.Ordinal)
    {
        // SIEM: drained by SecurityEventDispatcher's own lane per transport, off every request; a failed event is
        // dropped, so a back-off would only drop the events the lane holds through a short outage.
        ["src/IncidentManager.Web/Siem/WebhookTransport.cs"] = "SIEM lane",
        ["src/IncidentManager.Infrastructure/Siem/SyslogTransport.cs"] = "SIEM lane",
        // Background, once a day.
        ["src/IncidentManager.Web/Updates/UpdateCheckService.cs"] = "update check",
        // Seal copies run when a seal is made (a background job), each with its own timeout.
        ["src/IncidentManager.Infrastructure/Security/SealCopiers.cs"] = "seal copies",
        // Secret fetches are cached and bounded by their own timeout (minor: one shared lock, listed in C10).
        ["src/IncidentManager.Infrastructure/Secrets/CyberArkCcpSecretProvider.cs"] = "secret provider",
    };

    private static readonly Regex Connects = new(
        @"CreateClient\(|new\s+(SmtpClient|UdpClient|TcpClient|HttpClient|Socket)\(|SendMailAsync\(|Dns\.GetHost",
        RegexOptions.None, TimeSpan.FromSeconds(5));

    [Fact]
    public void Every_outbound_transport_backs_off_a_target_that_isnt_answering_or_is_listed()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) dir = dir.Parent;
        dir.Should().NotBeNull();
        var root = dir!.FullName;
        var sep = Path.DirectorySeparatorChar;

        var transports = Directory.EnumerateFiles(Path.Combine(root, "src"), "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
            .Where(f => !f.Contains($"{sep}obj{sep}", StringComparison.Ordinal) && !f.Contains($"{sep}bin{sep}", StringComparison.Ordinal))
            .Select(f => (Path: Path.GetRelativePath(root, f).Replace('\\', '/'), Text: File.ReadAllText(f)))
            .Where(f => Connects.IsMatch(f.Text))
            .ToList();

        transports.Should().Contain(t => t.Path.EndsWith("EmailSender.cs", StringComparison.Ordinal));
        transports.Where(t => !t.Text.Contains("OutboundCircuit", StringComparison.Ordinal) && !NotOnTheUserPath.ContainsKey(t.Path))
            .Select(t => t.Path).Should().BeEmpty("a send to a stalled host would hold every user action that makes one");
        NotOnTheUserPath.Keys.Should().BeSubsetOf(transports.Select(t => t.Path), "a listed transport that's gone is taken off the list");
    }
}
