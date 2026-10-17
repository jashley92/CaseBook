namespace IncidentManager.Application.Abstractions;

/// <summary>PROD-57: where evidence encryption stands.</summary>
public enum EvidenceKeyState
{
    /// <summary>Not turned on (Storage:Encryption:Enabled is false): files are stored as they arrive.</summary>
    Off,
    /// <summary>Turned on, but there's no integrity certificate or chain key to protect the key with.</summary>
    NotConfigured,
    /// <summary>The key exists, but no backup does yet (no recovery certificate, no shares issued): files are stored as
    /// they arrive until one does, so one lost certificate can't lose everything.</summary>
    NeedsBackup,
    /// <summary>New files are encrypted, and encrypted files open.</summary>
    Ready,
    /// <summary>The key is needed but can't be opened (a certificate missing, CyberArk down, every copy unreadable).
    /// Encrypted files can't be read or written until it's back; the rest of CaseBook works.</summary>
    Unavailable,
}

/// <summary>
/// PROD-57: the evidence (and report) master keys, held in memory only. New files are encrypted under the current key
/// when <see cref="State"/> is <see cref="EvidenceKeyState.Ready"/>; files name the key they were written with, by id.
/// </summary>
public interface IEvidenceKeyring
{
    EvidenceKeyState State { get; }

    /// <summary>The key new files are encrypted with, when encrypting.</summary>
    string? CurrentKeyId { get; }

    /// <summary>The master key with this id, or null when it isn't held (or the keyring is unavailable).</summary>
    byte[]? Key(string keyId);

    /// <summary>Why the state isn't Ready, in words an administrator can act on; null when it is (or off).</summary>
    string? Problem { get; }
}

/// <summary>PROD-57: an encrypted file was asked for while its key isn't held. The file is fine; the key needs restoring.</summary>
/// <summary>
/// PROD-56: the evidence store's folder isn't there while evidence is recorded (a share down, remapped or mounted
/// elsewhere). One answer for every file, "the store can't be reached", never "this file is missing".
/// </summary>
public sealed class EvidenceStoreUnreachableException(string location)
    : IOException($"The evidence store's folder ({location}) isn't there. It held evidence, so CaseBook doesn't recreate it: " +
                  "check that the share or volume is reachable and EvidenceStore:RootPath points at it.");

public sealed class EvidenceKeyUnavailableException(string keyId)
    : Exception($"The evidence key ({keyId}) isn't available on this server, so encrypted evidence and reports can't be read or " +
                "written. An administrator has been alerted.")
{
    public string KeyId { get; } = keyId;
}

/// <summary>Encryption off: every file stored and read as it is.</summary>
public sealed class NoEvidenceKeys : IEvidenceKeyring
{
    public static readonly NoEvidenceKeys Instance = new();
    public EvidenceKeyState State => EvidenceKeyState.Off;
    public string? CurrentKeyId => null;
    public byte[]? Key(string keyId) => null;
    public string? Problem => null;
}
