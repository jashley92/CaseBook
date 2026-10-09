using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Security;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>F-25: the audit chain hashed with a secret key, and where that key comes from.</summary>
public sealed class ChainKeyTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "im-chain-key-tests", Guid.NewGuid().ToString("N"));

    private sealed class Ring(params byte[][] keys) : IChainKeyring
    {
        public string? CurrentKeyId => keys.Length > 0 ? ChainKeyring.KeyIdOf(keys[0]) : null;
        public byte[]? Key(string keyId) => keys.FirstOrDefault(k => ChainKeyring.KeyIdOf(k) == keyId);
        public IReadOnlyList<string> KeyIds => keys.Select(ChainKeyring.KeyIdOf).ToList();
        public string? Source => "test";
    }

    private static readonly byte[] KeyA = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] KeyB = RandomNumberGenerator.GetBytes(32);

    private static AuditLogEntry Append(HashChainService svc, List<AuditLogEntry> chain, string summary)
    {
        var e = new AuditLogEntry { AtUtc = DateTimeOffset.UnixEpoch, Actor = "a", Action = AuditAction.Update, EntityType = "Case", Summary = summary };
        svc.ChainAppend(e, chain.LastOrDefault());
        chain.Add(e);
        return e;
    }

    private static List<AuditLogEntry> PlainThenKeyed()
    {
        var chain = new List<AuditLogEntry>();
        var plain = new HashChainService();
        Append(plain, chain, "before the key");
        Append(plain, chain, "still before");
        var keyed = new HashChainService(new Ring(KeyA));
        Append(keyed, chain, "after the key");
        Append(keyed, chain, "and after");
        return chain;
    }

    [Fact]
    public void History_before_the_key_keeps_its_plain_hash_and_the_whole_chain_verifies()
    {
        var chain = PlainThenKeyed();

        chain.Select(e => e.HashKeyId).Should().Equal(null, null, ChainKeyring.KeyIdOf(KeyA), ChainKeyring.KeyIdOf(KeyA));
        new HashChainService(new Ring(KeyA)).VerifyChain(chain).IsValid.Should().BeTrue();
    }

    [Fact]
    public void A_plain_entry_after_a_keyed_one_is_a_break()
    {
        // Someone with database access, but not the key, appends (or rewrites) an entry and computes its hash the
        // plain way so it links up. The keyed history before it gives it away.
        var chain = PlainThenKeyed();
        Append(new HashChainService(), chain, "forged without the key");

        var result = new HashChainService(new Ring(KeyA)).VerifyChain(chain);

        result.IsValid.Should().BeFalse();
        result.FirstBrokenSequence.Should().Be(5);
        result.Detail.Should().Contain("plain hash").And.Contain("keyed since entry #3");
    }

    [Fact]
    public void A_keyed_entry_altered_without_the_key_fails_its_hash()
    {
        var chain = PlainThenKeyed();
        chain[2].Summary = "altered";   // the attacker can't recompute the HMAC

        var result = new HashChainService(new Ring(KeyA)).VerifyChain(chain);

        result.IsValid.Should().BeFalse();
        result.FirstBrokenSequence.Should().Be(3);
    }

    [Fact]
    public void An_entry_under_a_key_this_server_doesnt_hold_is_a_break_that_names_the_key()
    {
        var chain = PlainThenKeyed();

        var result = new HashChainService(new Ring(KeyB)).VerifyChain(chain);

        result.IsValid.Should().BeFalse();
        result.FirstBrokenSequence.Should().Be(3);
        result.Detail.Should().Contain(ChainKeyring.KeyIdOf(KeyA)).And.Contain("doesn't hold");
    }

    [Fact]
    public void After_a_key_change_entries_under_the_retired_key_still_verify()
    {
        var chain = PlainThenKeyed();
        Append(new HashChainService(new Ring(KeyB, KeyA)), chain, "under the new key");

        chain[^1].HashKeyId.Should().Be(ChainKeyring.KeyIdOf(KeyB));
        new HashChainService(new Ring(KeyB, KeyA)).VerifyChain(chain).IsValid.Should().BeTrue();
    }

    // ---- Where the key comes from ----

    private sealed class FakeSecrets(Dictionary<string, string?> values) : ISecretProvider
    {
        public ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default) =>
            ValueTask.FromResult(configuredValue is not null && values.TryGetValue(configuredValue, out var v) ? v : null);
    }

    private ChainKeyring LoadRing(ChainKeyOptions key, ISecretProvider? secrets = null) =>
        new(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(_dir, "seal.pem"), ChainKey = key }), secrets);

    [Fact]
    public void Off_by_default_the_ring_is_empty()
    {
        var ring = LoadRing(new ChainKeyOptions());

        (ring.CurrentKeyId, ring.Source).Should().Be((null, null));
        ring.KeyIds.Should().BeEmpty();
    }

    [Fact]
    public void From_cyberark_with_retired_keys()
    {
        var secrets = new FakeSecrets(new()
        {
            ["@cyberark:Safe=S;Object=Chain"] = Convert.ToBase64String(KeyB),
            ["@cyberark:Safe=S;Object=Chain-2025"] = Convert.ToBase64String(KeyA),
        });

        var ring = LoadRing(new ChainKeyOptions
        {
            Enabled = true, Source = ChainKeySource.CyberArk, Secret = "@cyberark:Safe=S;Object=Chain",
            RetiredSecrets = ["@cyberark:Safe=S;Object=Chain-2025"]
        }, secrets);

        ring.CurrentKeyId.Should().Be(ChainKeyring.KeyIdOf(KeyB));
        ring.Key(ChainKeyring.KeyIdOf(KeyA)).Should().Equal(KeyA);
        ring.KeyIds.Should().HaveCount(2);
        ring.Source.Should().Be("CyberArk");
    }

    [Fact]
    public void A_cyberark_key_that_is_missing_short_or_not_base64_stops_startup()
    {
        ChainKeyring With(string? value) => LoadRing(new ChainKeyOptions { Enabled = true, Secret = "@cyberark:Safe=S;Object=C" },
            new FakeSecrets(new() { ["@cyberark:Safe=S;Object=C"] = value }));

        ((Action)(() => With(null))).Should().Throw<InvalidOperationException>().WithMessage("*couldn't be fetched from CyberArk*");
        ((Action)(() => With("not base64!"))).Should().Throw<InvalidOperationException>().WithMessage("*isn't base64*");
        ((Action)(() => With(Convert.ToBase64String(new byte[16])))).Should().Throw<InvalidOperationException>().WithMessage("*16 bytes*");
        ((Action)(() => LoadRing(new ChainKeyOptions { Enabled = true, Secret = Convert.ToBase64String(KeyA) }, new FakeSecrets(new()))))
            .Should().Throw<InvalidOperationException>().WithMessage("*must be an @cyberark:*");
    }

    [Fact]
    public void From_a_certificate_the_key_is_made_once_kept_encrypted_and_read_back()
    {
        using var rsa = RSA.Create(3072);
        using var ephemeral = new CertificateRequest("CN=CaseBook chain key test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var cert = X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx, "t"), "t",
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
        try
        {
            var options = new ChainKeyOptions
            {
                Enabled = true, Source = ChainKeySource.Certificate, CertificateThumbprint = cert.Thumbprint, StoreLocation = "CurrentUser"
            };

            var first = LoadRing(options);
            var file = Path.Combine(_dir, "chain-key.json");
            File.Exists(file).Should().BeTrue("the key is made on first start and kept encrypted");
            File.ReadAllText(file).Should().Contain(cert.Thumbprint);
            var second = LoadRing(options);

            second.CurrentKeyId.Should().Be(first.CurrentKeyId, "the same key is read back on the next start");

            // Rotation: the old file moves to the retired folder; a new key is made and the old one still loads.
            Directory.CreateDirectory(Path.Combine(_dir, "chain-retired"));
            File.Move(file, Path.Combine(_dir, "chain-retired", "2026.json"));
            var rotated = LoadRing(options);
            rotated.CurrentKeyId.Should().NotBe(first.CurrentKeyId);
            rotated.Key(first.CurrentKeyId!).Should().NotBeNull();
        }
        finally
        {
            store.Remove(cert);
            try { if (OperatingSystem.IsWindows() && RSACertificateExtensions.GetRSAPrivateKey(cert) is RSACng cng) cng.Key.Delete(); }
            catch (CryptographicException) { /* already gone */ }
        }
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }
}
