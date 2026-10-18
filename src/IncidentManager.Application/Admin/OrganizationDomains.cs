using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Observables;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Application.Admin;

/// <summary>
/// CAP-28 discovery: finds the organization's domains on the server's network once, in the background after start-up,
/// and keeps them for the app's lifetime (<see cref="IOrganizationDomains"/>). C10: the directory read runs on its own
/// thread and is waited on for <see cref="TimeLimit"/>; one look at a time (a second caller joins it); a look still
/// blocked after its limit isn't started again until it returns, and its late answer, a whole one, is kept. Start-up and
/// requests never wait on it. Not domain-joined, not Windows, or any failure means no domains, logged once per look.
/// </summary>
public sealed class OrganizationDomains : IOrganizationDomains, IHostedService
{
    /// <summary>How long one look may take, all told.</summary>
    public static readonly TimeSpan DefaultTimeLimit = TimeSpan.FromSeconds(5);

    private readonly IDomainDiscoverySource _source;
    private readonly ILogger<OrganizationDomains>? _log;
    private readonly TimeProvider _time;
    private readonly IHostApplicationLifetime? _lifetime;
    private readonly object _gate = new();
    private Task<DomainDiscovery>? _running;   // the look under way, joined by a second caller
    private Read? _hung;                       // a read that outlived its time limit and is still blocked
    private DomainDiscovery _current = DomainDiscovery.NotYet;

    public OrganizationDomains(IDomainDiscoverySource source, ILogger<OrganizationDomains>? log = null,
        IHostApplicationLifetime? lifetime = null, TimeProvider? time = null, TimeSpan? timeLimit = null)
    {
        _source = source;
        _log = log;
        _lifetime = lifetime;
        _time = time ?? TimeProvider.System;
        TimeLimit = timeLimit ?? DefaultTimeLimit;
    }

    public TimeSpan TimeLimit { get; }

    public DomainDiscovery Current
    {
        get { lock (_gate) return _current; }
    }

    // Started once the app is serving, so start-up never waits on the directory.
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_lifetime is null) _ = DiscoverAsync(CancellationToken.None);
        else _lifetime.ApplicationStarted.Register(() => _ = DiscoverAsync(CancellationToken.None));
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task<DomainDiscovery> DiscoverAsync(CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (_running is null)
            {
                if (_hung is not null) return Task.FromResult(_current);   // C10: not asked again until it returns
                // Task.Run: the look's end (which clears _running under _gate) can't come before it's recorded here.
                _running = Task.Run(LookAsync, CancellationToken.None);
            }
            return _running.WaitAsync(ct);
        }
    }

    private async Task<DomainDiscovery> LookAsync()
    {
        var read = new Read();
        DomainDiscovery? result = null;
        var timedOut = false;
        try
        {
            var reading = Task.Factory.StartNew(() => ReadOnItsThread(read), CancellationToken.None,
                TaskCreationOptions.LongRunning, TaskScheduler.Default);
            result = await reading.WaitAsync(TimeLimit, _time, CancellationToken.None);   // bounded by the time limit, not by a caller
        }
        catch (TimeoutException)
        {
            timedOut = true;
        }
        catch (Exception ex)
        {
            result = Failed(ex);
        }
        lock (_gate)
        {
            if (timedOut)
            {
                // An answer that came between the time limit and here is a whole one: kept. Otherwise the read is hung,
                // and hands its answer on itself when it comes (under this lock, so never before this is recorded).
                if (read.Done) result = read.Result;
                else _hung = read;
            }
            result ??= new DomainDiscovery(DomainDiscoveryState.TimedOut, [], _time.GetUtcNow());
            _current = result;
            _running = null;
        }
        Log(result);
        return result;
    }

    // On the read's own thread. A read that outlived its time limit hands its whole answer on when it comes.
    private DomainDiscovery ReadOnItsThread(Read read)
    {
        DomainDiscovery result;
        try
        {
            var raw = _source.Read();
            result = raw is null
                ? new DomainDiscovery(DomainDiscoveryState.NotDomainJoined, [], _time.GetUtcNow())
                : Normalized(raw, _time.GetUtcNow());
        }
        catch (Exception ex)
        {
            result = Failed(ex);
        }
        bool late;
        lock (_gate)
        {
            read.Done = true;
            read.Result = result;
            late = ReferenceEquals(_hung, read);
            if (late)
            {
                _hung = null;
                _current = result;
            }
        }
        if (late) Log(result, late: true);
        return result;
    }

    private DomainDiscovery Failed(Exception ex) =>
        new(DomainDiscoveryState.Failed, [], _time.GetUtcNow(), ex.GetType().Name);

    /// <summary>
    /// The names as a saved domain is stored (<see cref="RelatedExclusions.NormalizeDomain"/>), anything it refuses
    /// (a NetBIOS name, a public suffix) dropped and counted, each name once under its first source in
    /// <see cref="DiscoveredDomainSource"/> order (this domain before the forest root before the rest).
    /// </summary>
    public static DomainDiscovery Normalized(IEnumerable<DiscoveredDomain> raw, DateTimeOffset atUtc)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var kept = new List<DiscoveredDomain>();
        var refused = 0;
        foreach (var d in raw.OrderBy(d => d.Source))   // stable: the directory's order within a source
        {
            var name = RelatedExclusions.NormalizeDomain(d.Name, out _);
            if (name is null) refused++;
            else if (seen.Add(name)) kept.Add(d with { Name = name });
        }
        return new DomainDiscovery(DomainDiscoveryState.Found, kept, atUtc, Refused: refused);
    }

    private void Log(DomainDiscovery result, bool late = false)
    {
        if (_log is null) return;
        var when = late ? " (answered after its time limit)" : "";
        switch (result.State)
        {
            case DomainDiscoveryState.Found:
                _log.LogInformation("Found this server's organization domains{Late}: {Domains}. {Refused} name(s) that aren't full domain names left out.",
                    when, result.Domains.Count == 0 ? "none" : result.Described, result.Refused);
                break;
            case DomainDiscoveryState.NotDomainJoined:
                _log.LogInformation("This server isn't joined to an Active Directory domain, so no organization domains were found.");
                break;
            case DomainDiscoveryState.TimedOut:
                _log.LogWarning("Active Directory didn't list this server's domains within {Seconds} s; no organization domains are offered until it answers.",
                    TimeLimit.TotalSeconds);
                break;
            default:
                _log.LogWarning("Couldn't list this server's domains in Active Directory ({ErrorType}); no organization domains are offered.",
                    result.ErrorType);
                break;
        }
    }

    private sealed class Read
    {
        public bool Done;
        public DomainDiscovery? Result;
    }
}
