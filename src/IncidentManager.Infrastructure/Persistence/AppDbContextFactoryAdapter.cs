using IncidentManager.Application.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// Adapts EF Core's <see cref="IDbContextFactory{TContext}"/> to the application-layer
/// <see cref="IAppDbContextFactory"/> so handlers create per-operation contexts without depending on
/// EF types (mirrors how <see cref="IAppDbContext"/> keeps the Application layer off the concrete
/// <see cref="AppDbContext"/>). Registered scoped so each created context carries the circuit's scoped
/// audit-chain interceptor (see DependencyInjection).
/// </summary>
public sealed class AppDbContextFactoryAdapter : IAppDbContextFactory
{
    private readonly IDbContextFactory<AppDbContext> _inner;

    public AppDbContextFactoryAdapter(IDbContextFactory<AppDbContext> inner) => _inner = inner;

    public IAppDbContext CreateDbContext() => _inner.CreateDbContext();
}
