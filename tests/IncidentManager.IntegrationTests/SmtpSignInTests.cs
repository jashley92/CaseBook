using System.Net.Mail;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-05: the relay sign-in settings. Username and password, and integrated Windows sign-in, are mutually exclusive, and
/// half a username and password is a mistake to fix: each stops every send (fail closed) and says why. The password is
/// resolved per send, a reference that won't resolve stops the send, and the time limit is held to 5 to 300 seconds.
/// </summary>
public sealed class SmtpSignInTests
{
    private static string NewSecret() => "s-" + Guid.NewGuid().ToString("N");   // S2068: made at run time

    private static EmailOptions With(string user = "", string? secret = null, bool integrated = false, bool ssl = true) =>
        new() { SmtpUsername = user, SmtpPassword = secret ?? "", SmtpUseDefaultCredentials = integrated, EnableSsl = ssl };

    [Fact]
    public void The_modes_are_read_from_the_settings()
    {
        SmtpSignIn.Mode(With()).Should().Be(SmtpSignInMode.None);
        SmtpSignIn.Mode(With("casebook@contoso.example", NewSecret())).Should().Be(SmtpSignInMode.Password);
        SmtpSignIn.Mode(With(integrated: true)).Should().Be(SmtpSignInMode.Integrated);
        SmtpSignIn.InServerConfig(With()).Should().BeFalse("nothing set: the sign-in saved in Administration applies");
        SmtpSignIn.InServerConfig(With(integrated: true)).Should().BeTrue();
        SmtpSignIn.InServerConfig(With(secret: NewSecret())).Should().BeTrue("even half of one: the server's file wins, and says it's wrong");
    }

    [Theory]
    [InlineData("u", true, true, "SmtpUseDefaultCredentials")]   // both ways at once
    [InlineData("", true, true, "SmtpUseDefaultCredentials")]
    [InlineData("u", false, true, "SmtpUseDefaultCredentials")]
    [InlineData("", true, false, "without Email:SmtpUsername")]  // a password for nobody
    [InlineData("u", false, false, "without Email:SmtpPassword")]
    public async Task A_conflict_or_half_a_sign_in_is_named_and_stops_the_send(string user, bool secret, bool integrated, string named)
    {
        var o = With(user, secret ? NewSecret() : null, integrated);
        SmtpSignIn.Problem(o).Should().Contain(named);
        SmtpSignIn.Mode(o).Should().Be(SmtpSignInMode.Invalid);
        SmtpSignIn.Describe(o).Should().StartWith("Not usable");
        var send = () => SmtpSignIn.CredentialsAsync(o, null, CancellationToken.None);
        (await send.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain(named);
    }

    [Theory]
    [InlineData("literal", SmtpPasswordForm.Literal, "plain-text")]
    [InlineData("@cyberark:Safe=Mail;Object=Relay", SmtpPasswordForm.CyberArk, "CyberArk")]
    [InlineData("@protected:v1:0123456789ABCDEF0123456789ABCDEF01234567:AAAA", SmtpPasswordForm.Protected, "@protected:")]
    public void Server_configuration_shows_how_it_signs_in_never_with_what(string form, SmtpPasswordForm expected, string says)
    {
        var secret = form == "literal" ? NewSecret() : form;
        var o = With("casebook@contoso.example", secret);
        SmtpSignIn.PasswordForm(o.SmtpPassword).Should().Be(expected);
        SmtpSignIn.Describe(o).Should().Contain(says).And.NotContain(secret);
    }

    [Fact]
    public void A_plain_text_password_and_one_without_tls_are_warned_of()
    {
        SmtpSignIn.Warnings(With("u", NewSecret())).Should().ContainSingle().Which.Should().Contain("plain text");
        SmtpSignIn.Warnings(With("u", "@cyberark:Safe=M;Object=R", ssl: false)).Should().ContainSingle().Which.Should().Contain("EnableSsl");
        SmtpSignIn.Warnings(With(integrated: true, ssl: false)).Should().BeEmpty("no password crosses the network");
    }

    [Theory]
    [InlineData(1, 5)]
    [InlineData(30, 30)]
    [InlineData(301, 300)]
    [InlineData(-4, 5)]
    public void The_time_limit_is_held_to_its_bounds(int set, int seconds) =>
        SmtpSignIn.Timeout(new EmailOptions { SmtpTimeoutSeconds = set }).Should().Be(TimeSpan.FromSeconds(seconds));

    private sealed class Resolver(string? answer) : ISecretProvider
    {
        public ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default) => ValueTask.FromResult(answer);
    }

    [Fact]
    public async Task The_password_is_resolved_per_send_and_one_that_wont_resolve_stops_it()
    {
        var secret = NewSecret();
        var o = With(" casebook@contoso.example ", "@cyberark:Safe=Mail;Object=Relay");
        var credentials = await SmtpSignIn.CredentialsAsync(o, new Resolver(secret), CancellationToken.None);
        credentials!.UserName.Should().Be("casebook@contoso.example");
        credentials.Password.Should().Be(secret);

        var unresolved = () => SmtpSignIn.CredentialsAsync(o, new Resolver(null), CancellationToken.None);
        (await unresolved.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("CyberArk");
        var noProvider = () => SmtpSignIn.CredentialsAsync(o, null, CancellationToken.None);
        await noProvider.Should().ThrowAsync<InvalidOperationException>("without a provider only a literal works, never the reference's text");

        (await SmtpSignIn.CredentialsAsync(With("u", secret), null, CancellationToken.None))!.Password.Should().Be(secret);
        (await SmtpSignIn.CredentialsAsync(With(integrated: true), null, CancellationToken.None)).Should().BeNull("the client signs in as the app-pool account");
    }

    [Theory]
    [InlineData(530, true)]
    [InlineData(534, true)]
    [InlineData(535, true)]
    [InlineData(538, true)]
    [InlineData(454, false)]   // a temporary sign-in failure: a 4xx, tried again (BUG-626)
    [InlineData(550, false)]
    [InlineData(421, false)]
    public void A_refused_sign_in_is_told_by_its_code(int code, bool refused)
    {
        var ex = new SmtpException((SmtpStatusCode)code, "5.7.8 Error: authentication failed: <someone@contoso.example> relay reply");
        EmailSender.SignInRefused(ex).Should().Be(refused);
        if (!refused) return;
        EmailSender.Unreachable(ex).Should().BeFalse("the relay answered: it's not backed off (BUG-607)");
        SendOutcomes.Of(ex).Should().Be(SendOutcome.SignInRefused, "kept for the fix, as BUG-652's Blocked is, not deleted");
        var told = EmailSender.SignInRefusedText(EmailSender.StatusOf(ex));
        told.Should().Contain($"SMTP {code}").And.NotContain("relay reply").And.NotContain("@contoso.example");
    }

    [Fact]
    public void A_relay_that_refuses_an_unsigned_session_at_rcpt_doesnt_delete_the_email(/* CAP-05 */)
    {
        var ex = new SmtpFailedRecipientException((SmtpStatusCode)530, "<a@contoso.example>");
        SendOutcomes.Of(ex).Should().Be(SendOutcome.SignInRefused, "not Refused, which would delete it as the address's own fault");
    }
}
