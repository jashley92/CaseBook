using IncidentManager.Application.Abstractions;

namespace IncidentManager.Infrastructure.Realtime;

/// <summary>
/// Process-local, in-memory implementation of <see cref="ICasePresenceService"/>. Registered as a
/// singleton so every circuit shares one registry. Mirrors <see cref="CaseChangeNotifier"/>: a lock
/// guards the maps and change callbacks are dispatched on the thread pool so a slow (or gone)
/// subscriber never blocks a join/leave.
/// </summary>
public sealed class CasePresenceService : ICasePresenceService
{
    private readonly object _gate = new();
    private readonly Dictionary<Guid, List<Registration>> _byCase = new();
    private readonly Dictionary<Guid, List<Subscription>> _subs = new();

    public IDisposable Join(Guid caseId, string userId, string displayName, string circuitId)
    {
        var reg = new Registration(this, caseId, userId, displayName, circuitId);
        lock (_gate)
        {
            if (!_byCase.TryGetValue(caseId, out var list))
            {
                list = new List<Registration>();
                _byCase[caseId] = list;
            }
            list.Add(reg);
        }
        Publish(caseId);
        return reg;
    }

    public IReadOnlyList<CaseViewer> Viewers(Guid caseId)
    {
        lock (_gate)
        {
            if (!_byCase.TryGetValue(caseId, out var list) || list.Count == 0)
                return Array.Empty<CaseViewer>();

            // One entry per person even if they have the case open in several tabs.
            return list
                .GroupBy(r => r.UserId, StringComparer.OrdinalIgnoreCase)
                .Select(g => new CaseViewer(g.Key, g.First().DisplayName))
                .OrderBy(v => v.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
    }

    public IDisposable Subscribe(Guid caseId, Func<Task> onChanged)
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

    public void RemoveCircuit(string circuitId)
    {
        var affected = new List<Guid>();
        lock (_gate)
        {
            foreach (var (caseId, list) in _byCase)
            {
                if (list.RemoveAll(r => string.Equals(r.CircuitId, circuitId, StringComparison.Ordinal)) > 0)
                    affected.Add(caseId);
            }
            foreach (var caseId in affected)
                if (_byCase.TryGetValue(caseId, out var l) && l.Count == 0) _byCase.Remove(caseId);
        }
        foreach (var caseId in affected) Publish(caseId);
    }

    private void Remove(Registration reg)
    {
        bool removed;
        lock (_gate)
        {
            if (!_byCase.TryGetValue(reg.CaseId, out var list)) return;
            removed = list.Remove(reg);
            if (list.Count == 0) _byCase.Remove(reg.CaseId);
        }
        if (removed) Publish(reg.CaseId);
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

    private void Publish(Guid caseId)
    {
        Func<Task>[] handlers;
        lock (_gate)
        {
            handlers = _subs.TryGetValue(caseId, out var list) && list.Count > 0
                ? list.Select(s => s.Handler).ToArray()
                : Array.Empty<Func<Task>>();
        }
        foreach (var h in handlers)
            _ = Task.Run(async () => { try { await h(); } catch { /* subscriber disposed or errored */ } });
    }

    private sealed class Registration : IDisposable
    {
        private readonly CasePresenceService _owner;
        private bool _disposed;
        public Guid CaseId { get; }
        public string UserId { get; }
        public string DisplayName { get; }
        public string CircuitId { get; }

        public Registration(CasePresenceService owner, Guid caseId, string userId, string displayName, string circuitId)
        {
            _owner = owner;
            CaseId = caseId;
            UserId = userId;
            DisplayName = displayName;
            CircuitId = circuitId;
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
        private readonly CasePresenceService _owner;
        private bool _disposed;
        public Guid CaseId { get; }
        public Func<Task> Handler { get; }

        public Subscription(CasePresenceService owner, Guid caseId, Func<Task> handler)
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
