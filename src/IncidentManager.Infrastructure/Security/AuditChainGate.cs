namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// REL-05: process-wide serialisation of audit-chain appends. Both append paths — the SaveChanges
/// <see cref="Persistence.Interceptors.AuditChainInterceptor"/> and the read/export
/// <see cref="AuditWriter"/> — read the current chain head, then link a new entry onto it. Without
/// serialisation two concurrent appends can read the same head and try to write the same
/// <c>Sequence</c>/<c>PrevHash</c>, forking the chain that is the spine of the integrity guarantee.
///
/// The unique index on <c>AuditLogEntry.Sequence</c> is the ultimate backstop: a race that ever slipped
/// past this gate — e.g. across processes, which an in-process gate cannot cover — fails the save with a
/// constraint violation rather than silently forking. This gate closes the window for the app's normal
/// single-instance deployment, so concurrent appends serialise and commit cleanly instead of one of them
/// hitting that contention error. It is held from the head read through commit, so a waiter always reads
/// the just-committed entry as its head.
/// </summary>
internal static class AuditChainGate
{
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public static void Enter() => Gate.Wait();
    public static Task EnterAsync(CancellationToken ct) => Gate.WaitAsync(ct);
    public static void Exit() => Gate.Release();
}
