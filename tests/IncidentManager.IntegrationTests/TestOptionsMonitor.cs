using Microsoft.Extensions.Options;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// A minimal <see cref="IOptionsMonitor{TOptions}"/> whose <see cref="CurrentValue"/> can be swapped,
/// so tests can simulate an administered settings change taking effect at runtime. <see cref="Change"/> also tells
/// the listeners, as a reload does.
/// </summary>
public sealed class TestOptionsMonitor<T> : IOptionsMonitor<T>
{
    private readonly List<Action<T, string?>> _listeners = [];

    public TestOptionsMonitor(T value) => CurrentValue = value;

    public T CurrentValue { get; set; }
    public T Get(string? name) => CurrentValue;

    public IDisposable OnChange(Action<T, string?> listener)
    {
        lock (_listeners) _listeners.Add(listener);
        return new Subscription(this, listener);
    }

    /// <summary>Sets <see cref="CurrentValue"/> and calls each listener, as a configuration reload would.</summary>
    public void Change(T value)
    {
        CurrentValue = value;
        Action<T, string?>[] listeners;
        lock (_listeners) listeners = [.. _listeners];
        foreach (var l in listeners) l(value, null);
    }

    private sealed class Subscription(TestOptionsMonitor<T> owner, Action<T, string?> listener) : IDisposable
    {
        public void Dispose()
        {
            lock (owner._listeners) owner._listeners.Remove(listener);
        }
    }
}
