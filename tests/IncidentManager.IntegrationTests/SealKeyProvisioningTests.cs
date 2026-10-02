using FluentAssertions;
using IncidentManager.Infrastructure.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Outside Development the app never generates its own seal-signing key: a key it made for itself on the server
/// can't vouch for anything, so a missing key stops startup until one is provisioned out of band.
/// </summary>
public sealed class SealKeyProvisioningTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "casebook-sealkey", Guid.NewGuid().ToString("N"));

    private string KeyPath => Path.Combine(_dir, "keys", "seal-signing.pem");

    private RsaSealSigner Signer(bool allowGeneration) =>
        new(Options.Create(new SealSigningOptions { SigningKeyPath = KeyPath, AllowKeyGeneration = allowGeneration }));

    [Fact]
    public void A_missing_key_is_refused_and_not_written_when_generation_is_off()
    {
        var act = () => Signer(allowGeneration: false);
        act.Should().Throw<InvalidOperationException>().WithMessage("*Integrity:SigningKeyPath*provision the key out of band*");
        File.Exists(KeyPath).Should().BeFalse();
    }

    [Fact]
    public void A_provisioned_key_loads_without_generation()
    {
        string keyId;
        using (var generated = Signer(allowGeneration: true)) keyId = generated.KeyId;
        File.Exists(KeyPath).Should().BeTrue();

        using var loaded = Signer(allowGeneration: false);
        loaded.KeyId.Should().Be(keyId);
    }

    [Fact]
    public void Generation_is_off_by_default()
    {
        new SealSigningOptions().AllowKeyGeneration.Should().BeFalse();
        var act = () => new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = KeyPath }));
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void The_real_host_outside_Development_refuses_to_start_without_a_key_even_if_configuration_asks_to_generate()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Staging");
            b.UseSetting("Auth:AllowDevSignInOutsideDevelopment", "true");   // get past the auth fail-safe
            b.UseSetting("Integrity:AllowKeyGeneration", "true");           // must not be honored from config
            b.UseSetting("ConnectionStrings:Default", $"Data Source={Path.Combine(_dir, "casebook.db")}");
            b.UseSetting("Database:Provider", "Sqlite");
            b.UseSetting("Integrity:SigningKeyPath", KeyPath);
            b.UseSetting("Integrity:ExportPath", Path.Combine(_dir, "seals"));
            b.UseSetting("Integrity:AutoSeal:Enabled", "false");
        });
        var act = () => factory.CreateClient();
        act.Should().Throw<InvalidOperationException>().WithMessage("*seal-signing key*");
        File.Exists(KeyPath).Should().BeFalse();
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
