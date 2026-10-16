using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// C17: a race test of a gate shows the writers wait (started while the gate is held, none completes), but which of them
/// gets the gate next is up to the scheduler; v1.6.9's release failed on a test that assumed one order. The gate makes the
/// writers run one at a time, so every real run is one of the orders they can run in. This runs them in every order, one
/// after another, from a fresh arrangement each time, and checks each, so a test states what holds in each order rather
/// than what happened to hold in the one it saw.
/// </summary>
public static class RaceOrders
{
    /// <summary>One run: the order the writers ran in (indexes into the arranged list) and how each ended, by index.</summary>
    public sealed record Run(int Number, IReadOnlyList<int> Order, IReadOnlyList<Exception?> Outcomes)
    {
        /// <summary>The writers that threw, by index.</summary>
        public IReadOnlyList<int> Failed => Enumerable.Range(0, Outcomes.Count).Where(i => Outcomes[i] is not null).ToList();

        /// <summary>The writer that ran first.</summary>
        public int First => Order[0];

        public override string ToString() => $"run {Number}, order {string.Join(" then ", Order)}";
    }

    /// <summary>
    /// Arranges afresh (given the run number, for names that don't clash with an earlier run's) and runs the
    /// <paramref name="writers"/> it returns in every order, then checks the run.
    /// </summary>
    public static async Task ForEveryOrderAsync(int writers, Func<int, Task<IReadOnlyList<Func<Task>>>> arrange, Func<Run, Task> check)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(writers, 2);
        var number = 0;
        foreach (var order in Permutations(Enumerable.Range(0, writers).ToList()))
        {
            var calls = await arrange(number);
            if (calls.Count != writers) throw new InvalidOperationException($"Arranged {calls.Count} writers, not {writers}.");
            var outcomes = new Exception?[writers];
            foreach (var i in order)
                try { await calls[i](); }
                catch (Exception ex) { outcomes[i] = ex; }
            await check(new Run(number, order, outcomes));
            number++;
        }
    }

    private static IEnumerable<List<int>> Permutations(List<int> items)
    {
        if (items.Count <= 1) { yield return [.. items]; yield break; }
        foreach (var head in items)
            foreach (var tail in Permutations(items.Where(x => x != head).ToList()))
                yield return [head, .. tail];
    }
}

/// <summary>
/// Runs <c>during</c> once, just before the first save through the context it's attached to: a write that lands between a
/// service's check and its save. Shared by the race tests (it was a private copy in each).
/// </summary>
public sealed class BeforeFirstSave(Func<Task> during) : SaveChangesInterceptor
{
    private int _fired;

    /// <summary>Arms it again, for the next save.</summary>
    public void Reset() => Interlocked.Exchange(ref _fired, 0);

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _fired, 1) == 0) await during();
        return result;
    }
}

/// <summary>
/// C17: completes once a point has been reached <paramref name="times"/> times, so a test waits for a call (on another
/// thread) to get there instead of reading a counter after a sleep or a timeout and hoping it already has.
/// </summary>
public sealed class Entered(int times = 1)
{
    private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _left = times;

    public void Signal()
    {
        if (Interlocked.Decrement(ref _left) <= 0) _entered.TrySetResult();
    }

    /// <summary>Waits for the signal, failing the test after <paramref name="limit"/> (default 10 seconds).</summary>
    public Task WaitAsync(TimeSpan? limit = null) => _entered.Task.WaitAsync(limit ?? TimeSpan.FromSeconds(10));
}
