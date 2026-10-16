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

    // `if (... !circuit.TryEnter(...))`: the send is skipped when the circuit says no.
    private static readonly Regex GatesOnTryEnter = new(@"\bif\s*\([^;{]*!\s*[\w.]+\.TryEnter\(", RegexOptions.None, TimeSpan.FromSeconds(5));
    private static readonly Regex ReportsFailure = new(@"[\w.]+\.Failed\(\s*\w+\s*\)", RegexOptions.None, TimeSpan.FromSeconds(5));

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
        // BUG-615: naming the type isn't using it. A transport must gate its send on TryEnter's answer and report a
        // target that didn't answer (Failed); a bypassed TryEnter used to pass here.
        transports.Where(t => !NotOnTheUserPath.ContainsKey(t.Path) && !(GatesOnTryEnter.IsMatch(t.Text) && ReportsFailure.IsMatch(t.Text)))
            .Select(t => t.Path).Should().BeEmpty("a send to a stalled host would hold every user action that makes one");
        NotOnTheUserPath.Keys.Should().BeSubsetOf(transports.Select(t => t.Path), "a listed transport that's gone is taken off the list");
    }
}
