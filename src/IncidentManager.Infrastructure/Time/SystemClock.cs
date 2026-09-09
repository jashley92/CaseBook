using IncidentManager.Application.Abstractions;

namespace IncidentManager.Infrastructure.Time;

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
