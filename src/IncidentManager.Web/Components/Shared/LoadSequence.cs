namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// BUG-601 (C5): a load whose result replaces what's shown is dropped when a newer load started, or the component moved
/// on (a reset, another case, disposal) while it ran. Each load takes a ticket before its first await and assigns only
/// while that ticket is current:
/// <code>
/// private readonly LoadSequence _preview = new();
/// var t = _preview.Begin();
/// var result = await Import.PreviewAsync(text);
/// if (!_preview.IsCurrent(t)) return;   // a newer preview, a reset or a dispose took over
/// _result = result;
/// </code>
/// Call <see cref="Invalidate"/> from whatever makes the loads in flight meaningless (Reset, a case switch, Dispose).
/// </summary>
public sealed class LoadSequence
{
    private int _number;

    /// <summary>One load's place in the sequence.</summary>
    public readonly record struct Ticket(int Number);

    /// <summary>Starts a load: every load begun before it is no longer current.</summary>
    public Ticket Begin() => new(++_number);

    /// <summary>Whether no load has begun, and nothing was invalidated, since this one began.</summary>
    public bool IsCurrent(Ticket ticket) => ticket.Number == _number;

    /// <summary>Drops every load in flight (their results are no longer for what's shown).</summary>
    public void Invalidate() => _number++;
}

/// <summary>
/// BUG-601 (C5): <see cref="LoadSequence"/> per key, for loads that run side by side for different things (each
/// notice's deadline, each row's lookup): a load is dropped when a newer one for the same key started, or that key (or
/// everything) was invalidated. <see cref="IsCurrentFor"/> also tells an action whether the result it is about to act on
/// came from the newest load for the key it acts on.
/// <code>
/// private readonly KeyedLoad&lt;string&gt; _find = new();
/// var t = _find.Begin(number);
/// var found = await Cases.FindByNumberAsync(number);
/// if (!_find.IsCurrent(t)) return;
/// _existing = found; _existingFor = t;
/// // later, in Apply: if (!_find.IsCurrentFor(_existingFor, _number)) { refuse }
/// </code>
/// </summary>
public sealed class KeyedLoad<TKey> where TKey : notnull
{
    private readonly Dictionary<TKey, int> _latest = new();
    private int _number;

    /// <summary>One load: the key it was for and its place in the sequence.</summary>
    public readonly record struct Ticket(TKey Key, int Number);

    /// <summary>Starts a load for <paramref name="key"/>: earlier loads for that key are no longer current.</summary>
    public Ticket Begin(TKey key)
    {
        var t = new Ticket(key, ++_number);
        _latest[key] = t.Number;
        return t;
    }

    /// <summary>Whether this is still the newest load for its key, and it wasn't invalidated.</summary>
    public bool IsCurrent(Ticket ticket) => _latest.TryGetValue(ticket.Key, out var n) && n == ticket.Number;

    /// <summary>Whether <paramref name="ticket"/> is current and was for <paramref name="key"/>.</summary>
    public bool IsCurrentFor(Ticket? ticket, TKey key) =>
        ticket is { } t && EqualityComparer<TKey>.Default.Equals(t.Key, key) && IsCurrent(t);

    /// <summary>Drops the loads in flight for one key.</summary>
    public void Invalidate(TKey key) => _latest.Remove(key);

    /// <summary>Drops every load in flight.</summary>
    public void Invalidate() => _latest.Clear();
}
