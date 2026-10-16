using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace IncidentManager.Web.Security;

/// <summary>
/// Group SID -> account name (e.g. "AD\SOC-AppAdmins"), for matching role mappings made by name. A name found is kept
/// for the process lifetime (a group rename is picked up on the next app restart); BUG-223: a lookup that found no name
/// (an AD blip as much as an orphaned SID) is kept only for <see cref="RetryUnresolved"/>.
/// <para>
/// BUG-565: a sign-in's groups are translated on the request's path, so the SIDs not yet known are translated together
/// in one bounded call (<see cref="BoundedDirectoryCalls{T}"/>): waited on for <see cref="Timeout"/>, after which they
/// have no name this time (only mappings by SID match, failing closed) and are not kept as unresolved, and names that
/// land later are kept. With <see cref="MaxHung"/> translations still blocked none is started until one returns.
/// </para>
/// <para>
/// BUG-575: the answer says which SIDs got none (not in time, still blocked, or the directory failed), so a caller that
/// must not act on a partial answer (the token-owner check, the open-session re-check) can tell.
/// </para>
/// </summary>
public sealed class SidNames
{
    internal static readonly TimeSpan RetryUnresolved = TimeSpan.FromMinutes(5);

    /// <summary>BUG-565: how long a request waits for its groups' names. Longer than a display name's: a group not
    /// named in time doesn't give its name-mapped roles to that request.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    /// <summary>BUG-565: translations running at once, including ones still blocked after their callers gave up.</summary>
    public const int MaxInFlight = 16;

    /// <summary>BUG-565: translations still blocked after timing out, past which none is started.</summary>
    public const int MaxHung = 2;

    /// <summary>BUG-575: how soon a SID whose translation failed (the directory threw) is asked again.</summary>
    internal static readonly TimeSpan RetryFailed = TimeSpan.FromMinutes(1);

    /// <summary>BUG-575: the names found, and the SIDs that got no answer.</summary>
    public sealed record Answer(IReadOnlyDictionary<string, string> Names, IReadOnlySet<string> Unanswered)
    {
        public bool Complete => Unanswered.Count == 0;
    }

    // Failed: the directory gave no answer (it threw), as opposed to answering that the SID has no name.
    private readonly ConcurrentDictionary<string, (string? Name, DateTimeOffset RetryAfterUtc, bool Failed)> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Func<IReadOnlyList<string>, IReadOnlyDictionary<string, string>> _translate;
    private readonly BoundedDirectoryCalls<string?> _calls;
    private readonly TimeSpan _timeout;
    private readonly TimeProvider _time;

    /// <param name="translate">The account names of the SIDs it's given; a SID it leaves out has none (tests stand in for
    /// the directory here).</param>
    public SidNames(Func<IReadOnlyList<string>, IReadOnlyDictionary<string, string>>? translate = null,
        TimeSpan? timeout = null, TimeProvider? time = null)
    {
        _timeout = timeout ?? Timeout;
        _time = time ?? TimeProvider.System;
        _translate = translate ?? Translate;
        // The translation goes to this server's LSA, which asks each SID's domain: one domain here.
        _calls = new BoundedDirectoryCalls<string?>(Ask, Landed, _ => "", MaxInFlight, MaxHung);
    }

    /// <summary>The account names of those of <paramref name="values"/> that are SIDs and have one (found now, within
    /// the time limit, or earlier), and the SIDs that got no answer.</summary>
    public Answer Resolve(IEnumerable<string> values)
    {
        var sids = SidsOf(values);
        var wanted = Wanted(sids);
        if (wanted.Count > 0) _calls.Wait(wanted, _timeout);
        return Read(sids);
    }

    /// <summary>As <see cref="Resolve"/>, without holding the caller's thread while it waits.</summary>
    public async Task<Answer> ResolveAsync(IEnumerable<string> values)
    {
        var sids = SidsOf(values);
        var wanted = Wanted(sids);
        if (wanted.Count > 0) await _calls.WaitAsync(wanted, _timeout);
        return Read(sids);
    }

    private static List<string> SidsOf(IEnumerable<string> values) =>
        values.Where(v => v.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    private List<string> Wanted(List<string> sids)
    {
        var now = _time.GetUtcNow();
        return sids.Where(s => !_cache.TryGetValue(s, out var c) || (c.Name is null && now >= c.RetryAfterUtc)).ToList();
    }

    private Answer Read(List<string> sids)
    {
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var unanswered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var sid in sids)
        {
            // BUG-575: not translated in time, still blocked, past the hung limit, or the directory failed.
            if (!_cache.TryGetValue(sid, out var c) || c.Failed) unanswered.Add(sid);
            else if (c.Name is { } name) names[sid] = name;
        }
        return new Answer(names, unanswered);
    }

    // Every SID asked is in the answer (null: the directory has no name for it); a translation that throws hands on none.
    private IReadOnlyDictionary<string, string?> Ask(IReadOnlyList<string> sids)
    {
        var found = _translate(sids);
        var answers = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var sid in sids) answers[sid] = found.TryGetValue(sid, out var name) ? name : null;
        return answers;
    }

    private void Landed(IReadOnlyList<string> sids, IReadOnlyDictionary<string, string?> found)
    {
        var now = _time.GetUtcNow();
        foreach (var sid in sids)
        {
            if (!found.TryGetValue(sid, out var name))
                _cache[sid] = (null, now + RetryFailed, true);   // BUG-575: the directory failed: no answer, asked again soon
            else
                _cache[sid] = !string.IsNullOrWhiteSpace(name)
                    ? (name, DateTimeOffset.MaxValue, false)
                    : (null, now + RetryUnresolved, false);   // well-known/orphaned SID: tried again after RetryUnresolved
        }
    }

    private static IReadOnlyDictionary<string, string> Translate(IReadOnlyList<string> sids) =>
        OperatingSystem.IsWindows() ? TranslateOnWindows(sids) : new Dictionary<string, string>();

    // One lookup for all of them; one that can't be mapped stays a SID in the answer (forceSuccess: false).
    [SupportedOSPlatform("windows")]
    private static Dictionary<string, string> TranslateOnWindows(IReadOnlyList<string> sids)
    {
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var asked = new List<string>();
        var refs = new IdentityReferenceCollection();
        foreach (var s in sids)
        {
            try { refs.Add(new SecurityIdentifier(s)); asked.Add(s); }
            catch (ArgumentException) { /* not a well-formed SID: no name */ }
        }
        if (asked.Count == 0) return names;
        var translated = refs.Translate(typeof(NTAccount), forceSuccess: false);
        for (var i = 0; i < asked.Count && i < translated.Count; i++)
            if (translated[i] is NTAccount account) names[asked[i]] = account.Value;
        return names;
    }
}
