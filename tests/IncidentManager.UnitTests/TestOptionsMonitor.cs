using Microsoft.Extensions.Options;

namespace IncidentManager.UnitTests;

/// <summary>
/// A minimal <see cref="IOptionsMonitor{TOptions}"/> whose <see cref="CurrentValue"/> can be swapped,
/// so tests can simulate an administered settings change taking effect at runtime.
/// </summary>
public sealed class TestOptionsMonitor<T> : IOptionsMonitor<T>
{
    public TestOptionsMonitor(T value) => CurrentValue = value;

    public T CurrentValue { get; set; }
    public T Get(string? name) => CurrentValue;
    public IDisposable OnChange(Action<T, string?> listener) => new NoopDisposable();

    private sealed class NoopDisposable : IDisposable
    {
        public void Dispose() { }
    }
}
