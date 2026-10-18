using System.Net;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Secrets;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>CAP-05: how CaseBook signs in to the mail relay.</summary>
public enum SmtpSignInMode
{
    /// <summary>No sign-in: the relay takes mail from this host as it is (the default, as before).</summary>
    None,
    /// <summary><c>Email:SmtpUsername</c> with <c>Email:SmtpPassword</c>.</summary>
    Password,
    /// <summary><c>Email:SmtpUseDefaultCredentials</c>: the app-pool account, by integrated Windows authentication.</summary>
    Integrated,
    /// <summary>Settings that can't be used together, or half a username and password: no email is sent until fixed.</summary>
    Invalid,
}

/// <summary>CAP-05: the form <c>Email:SmtpPassword</c> is written in (status only; never the value).</summary>
public enum SmtpPasswordForm { None, Literal, CyberArk, Protected }

/// <summary>
/// CAP-05: the sign-in an administrator saved under Administration (in the database, its password encrypted with Data
/// Protection), used when server configuration sets none (<see cref="SmtpSignIn.InServerConfig"/>). Read per send, so
/// a change on the form applies without a restart.
/// </summary>
public interface ISmtpSignInSource
{
    /// <summary>
    /// The saved mode and, for a password sign-in, its credentials. Throws <see cref="InvalidOperationException"/>, naming
    /// no secret, when the saved password is missing or can't be decrypted here (fail closed: the mail is held).
    /// </summary>
    Task<(SmtpSignInMode Mode, System.Net.NetworkCredential? Credentials)> ResolveAsync(CancellationToken ct);
}

/// <summary>
/// CAP-05: reads the relay sign-in settings (<see cref="EmailOptions"/>): which mode they make, what's wrong with them
/// (startup and Diagnostics say so), and the credentials for a send. Username and password, and integrated sign-in,
/// are mutually exclusive; a mix stops every send (held, BUG-652) rather than guessing which was meant.
/// </summary>
public static class SmtpSignIn
{
    public const int MinTimeoutSeconds = 5;
    public const int MaxTimeoutSeconds = 300;

    public static SmtpSignInMode Mode(EmailOptions o) => Problem(o) is not null
        ? SmtpSignInMode.Invalid
        : o.SmtpUseDefaultCredentials ? SmtpSignInMode.Integrated
        : HasUsername(o) ? SmtpSignInMode.Password
        : SmtpSignInMode.None;

    /// <summary>
    /// Whether server configuration sets the sign-in (any of Email:SmtpUsername, Email:SmtpPassword or
    /// Email:SmtpUseDefaultCredentials). It then wins over the one saved in Administration, which the form shows read-only.
    /// </summary>
    public static bool InServerConfig(EmailOptions o) =>
        o.SmtpUseDefaultCredentials || HasUsername(o) || !string.IsNullOrWhiteSpace(o.SmtpPassword);

    public static SmtpPasswordForm PasswordForm(string? password) =>
        string.IsNullOrWhiteSpace(password) ? SmtpPasswordForm.None
        : ProtectedSecret.IsProtected(password) ? SmtpPasswordForm.Protected
        : SecretReference.IsReference(password) ? SmtpPasswordForm.CyberArk
        : SmtpPasswordForm.Literal;

    /// <summary>Why the sign-in settings can't be used, or null when they can.</summary>
    public static string? Problem(EmailOptions o)
    {
        var password = !string.IsNullOrWhiteSpace(o.SmtpPassword);
        if (o.SmtpUseDefaultCredentials && (HasUsername(o) || password))
            return "Email:SmtpUseDefaultCredentials is on and Email:SmtpUsername or Email:SmtpPassword is set too. They're " +
                   "different ways to sign in to the relay: keep one, and clear the other.";
        if (password && !HasUsername(o))
            return "Email:SmtpPassword is set without Email:SmtpUsername. Set the account to sign in as, or clear the password.";
        if (HasUsername(o) && !password)
            return "Email:SmtpUsername is set without Email:SmtpPassword. Set its password (a @protected: value, a @cyberark: " +
                   "reference or a literal), or clear the username.";
        return null;
    }

    /// <summary>Things that work but deserve a word on Diagnostics: a password in plain text, or sent without TLS.</summary>
    public static IReadOnlyList<string> Warnings(EmailOptions o)
    {
        var warnings = new List<string>();
        if (Mode(o) != SmtpSignInMode.Password) return warnings;
        if (PasswordForm(o.SmtpPassword) == SmtpPasswordForm.Literal)
            warnings.Add("Email:SmtpPassword is plain text in the configuration. Write it as a @protected: value " +
                         "(casebook-keytool protect-secret) or a @cyberark: reference.");
        if (!o.EnableSsl)
            warnings.Add("Email:EnableSsl is off, so the relay password crosses the network unencrypted. Turn it on unless " +
                         "the relay is on this host.");
        return warnings;
    }

    /// <summary>The sign-in, for Server configuration: status only, never a value.</summary>
    public static string Describe(EmailOptions o) => Mode(o) switch
    {
        SmtpSignInMode.None => "None (the relay takes mail from this host without a sign-in)",
        SmtpSignInMode.Integrated => "Integrated Windows authentication, as the app-pool account",
        SmtpSignInMode.Password => PasswordForm(o.SmtpPassword) switch
        {
            SmtpPasswordForm.Protected => "Username, with a @protected: password",
            SmtpPasswordForm.CyberArk => "Username, with the password from CyberArk",
            _ => "Username, with a plain-text password",
        },
        _ => "Not usable: " + Problem(o),
    };

    /// <summary>A send's time limit: <see cref="EmailOptions.SmtpTimeoutSeconds"/>, held to 5 to 300 seconds.</summary>
    public static TimeSpan Timeout(EmailOptions o) =>
        TimeSpan.FromSeconds(Math.Clamp(o.SmtpTimeoutSeconds, MinTimeoutSeconds, MaxTimeoutSeconds));

    /// <summary>
    /// The username and password to sign in with, its password resolved through <paramref name="secrets"/> (without one,
    /// only a literal works); null for no sign-in and for integrated (the client then uses the app-pool account's). Throws
    /// <see cref="InvalidOperationException"/>, naming no secret, when the settings conflict or the password won't
    /// resolve: fail closed, never a send without the sign-in that was asked for.
    /// </summary>
    public static async Task<NetworkCredential?> CredentialsAsync(EmailOptions o, ISecretProvider? secrets, CancellationToken ct)
    {
        switch (Mode(o))
        {
            case SmtpSignInMode.None or SmtpSignInMode.Integrated: return null;
            case SmtpSignInMode.Invalid: throw new InvalidOperationException(Problem(o));
        }
        var form = PasswordForm(o.SmtpPassword);
        var password = secrets is not null
            ? await secrets.ResolveAsync(o.SmtpPassword, ct).ConfigureAwait(false)
            : form == SmtpPasswordForm.Literal ? o.SmtpPassword : null;
        if (string.IsNullOrEmpty(password))
            throw new InvalidOperationException(form switch
            {
                SmtpPasswordForm.Protected => "The SMTP password (a @protected: value) couldn't be opened on this server; see the log " +
                                              "for why, and check the app-pool account can read the certificate's private key.",
                SmtpPasswordForm.CyberArk => "The SMTP password couldn't be fetched from CyberArk; see Diagnostics, Secret resolution.",
                _ => "The SMTP password couldn't be resolved.",
            });
        return new NetworkCredential(o.SmtpUsername.Trim(), password);
    }

    private static bool HasUsername(EmailOptions o) => !string.IsNullOrWhiteSpace(o.SmtpUsername);
}
