using IncidentManager.Domain.Entities;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// F-27: an optional extra copy of each seal outside CaseBook (an email digest to a retained mailbox, a timestamp from an
/// internal RFC 3161 authority). Each is registered only when configured. A failure never undoes the seal: it's recorded
/// in <see cref="SealCopyStatus"/>, logged and sent to the SIEM as event 5005.
/// </summary>
public interface ISealCopier
{
    /// <summary>The destination's name, as Diagnostics and the Integrity page show it.</summary>
    string Name { get; }

    /// <summary>Copies the seal; throws with a short, non-secret reason when it can't.</summary>
    Task CopyAsync(IntegritySeal seal, CancellationToken ct = default);
}
