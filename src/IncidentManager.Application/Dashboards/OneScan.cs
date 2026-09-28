using System.Linq.Expressions;
using System.Reflection;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Dashboards;

/// <summary>
/// F-08: many counts and averages over the same rows in a single table scan. Each registered figure becomes a
/// conditional aggregate (COUNT(CASE WHEN …), AVG(…)) in one SELECT, instead of one query per figure. Measured on
/// SQL Server at 100k cases, serial plans: ~20 separate scans took several times longer than one.
/// Register figures, run once, then read each through the accessor its registration returned.
/// </summary>
internal sealed class OneScan<T>
{
    private readonly List<Expression<Func<T, bool>>> _counts = [];
    private readonly List<Expression<Func<T, double?>>> _averages = [];
    private Slots? _result;

    /// <summary>Counts the rows matching <paramref name="predicate"/>.</summary>
    public Func<int> Count(Expression<Func<T, bool>> predicate)
    {
        // A filter that can never match (for example SLA figures with no targets configured) is 0 without asking the
        // database; SQL Server rejects the COUNT(NULL) it would otherwise translate to.
        if (predicate.Body is ConstantExpression { Value: false }) return () => 0;
        var slot = Add(_counts, predicate, Slots.CountSlots.Length);
        return () => (int)Slots.CountSlots[slot].GetValue(Result)!;
    }

    /// <summary>Averages <paramref name="value"/> over the rows where it isn't null (as SQL's AVG does).</summary>
    public Func<double?> Average(Expression<Func<T, double?>> value)
    {
        var slot = Add(_averages, value, Slots.AverageSlots.Length);
        return () => (double?)Slots.AverageSlots[slot].GetValue(Result);
    }

    public async Task RunAsync(IQueryable<T> source, CancellationToken ct)
    {
        var group = Expression.Parameter(typeof(IGrouping<int, T>), "g");
        var bindings = _counts.Select((p, i) => Expression.Bind(Slots.CountSlots[i], Expression.Call(CountMethod, group, p)))
            .Concat(_averages.Select((v, i) => Expression.Bind(Slots.AverageSlots[i], Expression.Call(AverageMethod, group, v))));
        var selector = Expression.Lambda<Func<IGrouping<int, T>, Slots>>(
            Expression.MemberInit(Expression.New(typeof(Slots)), bindings), group);

        // One group holding every row; no rows at all means every count is 0 and every average is null.
        _result = await source.GroupBy(_ => 1).Select(selector).FirstOrDefaultAsync(ct) ?? new Slots();
    }

    private Slots Result => _result ?? throw new InvalidOperationException("Run the scan before reading its figures.");

    private static int Add<TItem>(List<TItem> list, TItem item, int capacity)
    {
        if (list.Count == capacity) throw new InvalidOperationException($"One scan holds at most {capacity} of these figures.");
        list.Add(item);
        return list.Count - 1;
    }

    private static readonly MethodInfo CountMethod = typeof(Enumerable).GetMethods()
        .Single(m => m.Name == nameof(Enumerable.Count) && m.GetParameters().Length == 2).MakeGenericMethod(typeof(T));

    private static readonly MethodInfo AverageMethod = typeof(Enumerable).GetMethods()
        .Single(m => m.Name == nameof(Enumerable.Average) && m.IsGenericMethodDefinition && m.GetParameters().Length == 2
                     && m.GetParameters()[1].ParameterType.GetGenericArguments()[1] == typeof(double?))
        .MakeGenericMethod(typeof(T));

    /// <summary>The projection target: fixed slots EF can materialize.</summary>
    internal sealed class Slots
    {
        public int C0 { get; set; } public int C1 { get; set; } public int C2 { get; set; } public int C3 { get; set; }
        public int C4 { get; set; } public int C5 { get; set; } public int C6 { get; set; } public int C7 { get; set; }
        public int C8 { get; set; } public int C9 { get; set; } public int C10 { get; set; } public int C11 { get; set; }
        public int C12 { get; set; } public int C13 { get; set; } public int C14 { get; set; } public int C15 { get; set; }
        public int C16 { get; set; } public int C17 { get; set; } public int C18 { get; set; } public int C19 { get; set; }
        public int C20 { get; set; } public int C21 { get; set; } public int C22 { get; set; } public int C23 { get; set; }
        public double? A0 { get; set; } public double? A1 { get; set; } public double? A2 { get; set; } public double? A3 { get; set; }

        internal static readonly PropertyInfo[] CountSlots = Enumerable.Range(0, 24).Select(i => typeof(Slots).GetProperty($"C{i}")!).ToArray();
        internal static readonly PropertyInfo[] AverageSlots = Enumerable.Range(0, 4).Select(i => typeof(Slots).GetProperty($"A{i}")!).ToArray();
    }
}
