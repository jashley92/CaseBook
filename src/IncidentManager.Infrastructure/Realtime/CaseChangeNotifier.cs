using IncidentManager.Application.Abstractions;

namespace IncidentManager.Infrastructure.Realtime;

/// <summary>
/// Process-local, in-memory implementation of <see cref="ICaseChangeNotifier"/>. Registered as a
/// singleton so every circuit shares the same subscriber registry; handlers are dispatched on the
/// thread pool so a slow (or gone) subscriber never blocks the publisher.
/// </summary>
public sealed class CaseChangeNotifier : ICaseChangeNotifier
{
    private readonly object _gate = new();
    private readonly Dictionary<Guid, List<Subscription>> _subs = new();
    private readonly List<GlobalSubscription> _globalSubs = new();

    public IDisposable Subscribe(Guid caseId, Func<string, Task> onChanged)
    {
        var sub = new Subscription(this, caseId, onChanged);
        lock (_gate)
        {
            if (!_subs.TryGetValue(caseId, out var list))
            {
                list = new List<Subscription>();
                _subs[caseId] = list;
            }
            list.Add(sub);
        }
        return sub;
    }

    public IDisposable SubscribeAll(Func<Guid, string, Task> onAnyChanged)
    {
        var sub = new GlobalSubscription(this, onAnyChanged);
        lock (_gate) _globalSubs.Add(sub);
        return sub;
    }

    public void Publish(Guid caseId, string actorId)
    {
        Func<string, Task>[] handlers;
        Func<Guid, string, Task>[] globalHandlers;
        lock (_gate)
        {
            handlers = _subs.TryGetValue(caseId, out var list) && list.Count > 0
                ? list.Select(s => s.Handler).ToArray()
                : Array.Empty<Func<string, Task>>();
            globalHandlers = _globalSubs.Count > 0
                ? _globalSubs.Select(s => s.Handler).ToArray()
                : Array.Empty<Func<Guid, string, Task>>();
        }
        foreach (var h in handlers)
            _ = Task.Run(async () => { try { await h(actorId); } catch { /* subscriber disposed or errored */ } });
        foreach (var h in globalHandlers)
            _ = Task.Run(async () => { try { await h(caseId, actorId); } catch { /* subscriber disposed or errored */ } });
    }

    private void Remove(Subscription sub)
    {
        lock (_gate)
        {
            if (!_subs.TryGetValue(sub.CaseId, out var list)) return;
            list.Remove(sub);
            if (list.Count == 0) _subs.Remove(sub.CaseId);
        }
    }

    private void Remove(GlobalSubscription sub)
    {
        lock (_gate) _globalSubs.Remove(sub);
    }

    private sealed class GlobalSubscription : IDisposable
    {
        private readonly CaseChangeNotifier _owner;
        private bool _disposed;
        public Func<Guid, string, Task> Handler { get; }

        public GlobalSubscription(CaseChangeNotifier owner, Func<Guid, string, Task> handler)
        {
            _owner = owner;
            Handler = handler;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _owner.Remove(this);
        }
    }

    private sealed class Subscription : IDisposable
    {
        private readonly CaseChangeNotifier _owner;
        private bool _disposed;
        public Guid CaseId { get; }
        public Func<string, Task> Handler { get; }

        public Subscription(CaseChangeNotifier owner, Guid caseId, Func<string, Task> handler)
        {
            _owner = owner;
            CaseId = caseId;
            Handler = handler;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _owner.Remove(this);
        }
    }
}
