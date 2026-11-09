namespace IncidentManager.TestSupport;

/// <summary>
/// How tests wait, shared by both test projects (linked in from <c>tests/Shared</c>). Two rules: wait for a condition,
/// never for a fixed time; and a limit on something that should finish is a hang guard, so it's generous. A
/// healthy run never waits it out, and a busy machine (CI, or several suites at once) can be many times slower than an
/// idle one: a tight limit fails tests that are fine. See docs/development/testing.md.
/// </summary>
public static class Waits
{
    /// <summary>The limit on anything that should finish: a save, a host starting, a signal from another thread. Long, so
    /// only a real hang (a gate never released, a deadlock) reaches it.</summary>
    public static readonly TimeSpan Hang = TimeSpan.FromMinutes(3);

    /// <summary>How long <see cref="Until(Func{bool}, TimeSpan?, string?)"/> waits by default.</summary>
    public static readonly TimeSpan Poll = TimeSpan.FromSeconds(30);

    /// <summary>Waits until <paramref name="condition"/> holds, checking every 10 ms; throws a <see cref="TimeoutException"/>
    /// naming <paramref name="what"/> if it doesn't within <paramref name="limit"/>.</summary>
    public static async Task Until(Func<bool> condition, TimeSpan? limit = null, string? what = null)
    {
        var until = DateTime.UtcNow + (limit ?? Poll);
        while (!condition())
        {
            if (DateTime.UtcNow > until) throw new TimeoutException($"Waited {(limit ?? Poll).TotalSeconds:N0} s for {what ?? "a condition"}.");
            await Task.Delay(10);
        }
    }

    /// <summary>Waits until <paramref name="condition"/> holds (an async check: a query, a lookup).</summary>
    public static async Task Until(Func<Task<bool>> condition, TimeSpan? limit = null, string? what = null)
    {
        var until = DateTime.UtcNow + (limit ?? Poll);
        while (!await condition())
        {
            if (DateTime.UtcNow > until) throw new TimeoutException($"Waited {(limit ?? Poll).TotalSeconds:N0} s for {what ?? "a condition"}.");
            await Task.Delay(10);
        }
    }

    /// <summary>Waits until <paramref name="next"/> gives a value <paramref name="done"/> accepts, and returns it.</summary>
    public static async Task<T> Until<T>(Func<Task<T>> next, Func<T, bool> done, TimeSpan? limit = null, string? what = null)
    {
        var until = DateTime.UtcNow + (limit ?? Poll);
        while (true)
        {
            var value = await next();
            if (done(value)) return value;
            if (DateTime.UtcNow > until) throw new TimeoutException($"Waited {(limit ?? Poll).TotalSeconds:N0} s for {what ?? "a condition"}.");
            await Task.Delay(10);
        }
    }
}
