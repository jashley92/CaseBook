namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Creates short-lived <see cref="IAppDbContext"/> instances scoped to a single unit of work (H-08).
/// Blazor Server shares one DI scope for a whole circuit, so a held context would be used concurrently
/// by components rendering in the same pass ("a second operation was started on this context"). Services
/// instead create a fresh context per operation and dispose it with <c>using</c>, so no context is ever
/// shared across renders and each has its own connection.
/// </summary>
public interface IAppDbContextFactory
{
    /// <summary>Creates a new context. The caller owns it and must dispose it (prefer <c>using</c>).</summary>
    IAppDbContext CreateDbContext();
}
