using System.Security.Cryptography;

namespace IncidentManager.Application.Abstractions;

/// <summary>
/// The signature algorithms a seal or configuration bundle can record. New signatures use RSASSA-PSS; releases before
/// v1.4.0 signed with RSASSA-PKCS1-v1_5, and those signatures still verify, each by the algorithm it records, so an
/// upgraded site's earlier seals stay valid. Anything else fails verification.
/// </summary>
public static class SealAlgorithms
{
    public const string Pss = "RSASSA-PSS-SHA256";
    public const string LegacyPkcs1 = "RSASSA-PKCS1-v1_5-SHA256";

    /// <summary>The padding for a recorded algorithm (none recorded means the current one), or null when it's unknown.</summary>
    public static RSASignaturePadding? PaddingFor(string? algorithm) => algorithm switch
    {
        null or "" or Pss => RSASignaturePadding.Pss,
        LegacyPkcs1 => RSASignaturePadding.Pkcs1,
        _ => null
    };
}
