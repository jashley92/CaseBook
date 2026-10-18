using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace IncidentManager.Application.Evidence;

/// <summary>
/// PROD-56: uploads arriving in parts (files over <see cref="InPageMaxBytes"/>), held in memory between their requests.
/// PROD-59: each one's state is also kept beside its parts, so an upload cut off (a restart, the tab closed, the network
/// lost) resumes when the person picks the same file again, within <see cref="IdleLimit"/>. Singleton;
/// <see cref="EvidenceService"/> does the checks around each step.
/// </summary>
public sealed class EvidenceUploadSessions
{
    /// <summary>The size of each part: under IIS's default 30 MB request limit, so no server change is needed.</summary>
    public const int PartBytes = 8 * 1024 * 1024;

    /// <summary>Files up to this size upload in the page as before; larger ones in parts.</summary>
    public const long InPageMaxBytes = 100L * 1024 * 1024;

    /// <summary>Uploads one person may have in progress at once.</summary>
    public const int MaxPerUser = 3;

    /// <summary>An upload with no part for this long is abandoned and its parts deleted.</summary>
    public static readonly TimeSpan IdleLimit = TimeSpan.FromHours(24);

    /// <summary>A finished upload is remembered this long, so a repeated "complete" answers with the same record.</summary>
    public static readonly TimeSpan DoneKept = TimeSpan.FromHours(1);

    internal sealed class Session(string id, string userId, Guid caseId, string fileName, string contentType, string? description,
        long size, string incoming, DateTimeOffset now)
    {
        public string Id { get; } = id;
        public string UserId { get; } = userId;
        public Guid CaseId { get; } = caseId;
        public string FileName { get; } = fileName;
        public string ContentType { get; } = contentType;
        public string? Description { get; } = description;
        public long Size { get; } = size;
        public string Incoming { get; } = incoming;
        public int NextPart { get; set; }
        public long Committed { get; set; }
        public IncrementalHash Hash { get; } = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        public SemaphoreSlim Gate { get; } = new(1, 1);   // one step of an upload at a time
        public DateTimeOffset LastActivity { get; set; } = now;
        public Guid? EvidenceId { get; set; }             // set once recorded
        public bool Ended { get; set; }                    // recorded or abandoned
        public int Parts => (int)((Size + PartBytes - 1) / PartBytes);

        // Review finding 4: the part being written and its SHA-256, kept until it's committed. A write that failed part-way
        // is retried at the same offset, so its chunks are sealed again under the same file key and chunk nonces; that's
        // only safe with the same bytes. A retry with different bytes (the file changed under the browser) ends the upload.
        public int PendingPart { get; set; } = -1;
        public byte[]? PendingHash { get; set; }

        /// <summary>PROD-59: the SHA-256 of each part committed, in order: after a restart (when the running hash is gone)
        /// the read-back checks every part against these and takes the file's hash from what it reads.</summary>
        public List<string> PartHashes { get; init; } = [];

        /// <summary>PROD-59: the SHA-256 of the file's first megabyte, from the browser, so a resume is the same file.</summary>
        public string? Sample { get; set; }

        /// <summary>PROD-59: restored after a restart: <see cref="Hash"/> holds nothing, the parts' hashes stand in.</summary>
        public bool Resumed { get; init; }

        internal State ToState() => new(Id, UserId, CaseId, FileName, ContentType, Description, Size, Incoming, NextPart, Committed,
            [.. PartHashes], Sample, PendingPart, PendingHash is null ? null : Convert.ToHexString(PendingHash), LastActivity);

        /// <summary>Review finding 11: once ended, the running hash isn't needed again (every later step checks Ended first).</summary>
        public void Release() => Hash.Dispose();
    }

    /// <summary>PROD-59: what's kept on disk for an upload (no secrets: names, sizes, offsets and hashes).</summary>
    internal sealed record State(string Id, string UserId, Guid CaseId, string FileName, string ContentType, string? Description,
        long Size, string Incoming, int NextPart, long Committed, List<string> PartHashes, string? Sample, int PendingPart,
        string? PendingHash, DateTimeOffset LastActivity);

    private static readonly System.Text.Json.JsonSerializerOptions StateJson = new(System.Text.Json.JsonSerializerDefaults.Web);

    internal static string Serialize(Session s) => System.Text.Json.JsonSerializer.Serialize(s.ToState(), StateJson);

    /// <summary>PROD-59: puts back an upload from its saved state (after a restart); false when it doesn't hold together.</summary>
    internal bool Restore(string incoming, string json)
    {
        State? st;
        try { st = System.Text.Json.JsonSerializer.Deserialize<State>(json, StateJson); }
        catch (System.Text.Json.JsonException) { return false; }
        if (st is null || st.Incoming != incoming || st.Id.Length != 32 || st.Size <= 0 || st.Committed < 0 || st.Committed > st.Size
            || st.NextPart < 0 || st.PartHashes.Count != st.NextPart) return false;
        var s = new Session(st.Id, st.UserId, st.CaseId, st.FileName, st.ContentType, st.Description, st.Size, st.Incoming, st.LastActivity)
        {
            NextPart = st.NextPart, Committed = st.Committed, PartHashes = [.. st.PartHashes], Sample = st.Sample, Resumed = true,
            PendingPart = st.PendingPart, PendingHash = st.PendingHash is null ? null : Convert.FromHexString(st.PendingHash),
        };
        return _sessions.TryAdd(s.Id, s);
    }

    /// <summary>PROD-59: this person's unfinished uploads to a case, to offer resuming.</summary>
    internal List<Session> Unfinished(string userId, Guid caseId) =>
        _sessions.Values.Where(s => s.UserId == userId && s.CaseId == caseId && !s.Ended).OrderBy(s => s.LastActivity).ToList();

    /// <summary>The parts files of uploads still held, which a sweep keeps.</summary>
    internal List<string> HeldIncoming() => _sessions.Values.Where(s => !s.Ended).Select(s => s.Incoming).ToList();

    private readonly ConcurrentDictionary<string, Session> _sessions = new(StringComparer.Ordinal);
    private readonly object _create = new();

    internal Session Create(string userId, Guid caseId, string fileName, string contentType, string? description, long size,
        string incoming, DateTimeOffset now)
    {
        lock (_create)   // the per-person cap is checked and taken together
        {
            if (_sessions.Values.Count(s => s.UserId == userId && !s.Ended) >= MaxPerUser)
                throw new ArgumentException($"You have {MaxPerUser} uploads in progress. Wait for one to finish, then try again.");
            // 128 random bits, not a GUID: an upload's id is what lets its parts in, alongside the person and the token.
            var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            var session = new Session(id, userId, caseId, fileName, contentType, description, size, incoming, now);
            _sessions[id] = session;
            return session;
        }
    }

    /// <summary>The upload with this id, if it's this person's (anyone else's reads as not found).</summary>
    internal Session? Find(string id, string userId) =>
        _sessions.TryGetValue(id, out var s) && s.UserId == userId ? s : null;

    internal void Forget(Session s)
    {
        _sessions.TryRemove(s.Id, out _);
        s.Release();
    }

    /// <summary>Uploads idle past <see cref="IdleLimit"/>, and finished ones past <see cref="DoneKept"/>, to drop.</summary>
    internal List<Session> Stale(DateTimeOffset now) =>
        _sessions.Values.Where(s => now - s.LastActivity > (s.Ended ? DoneKept : IdleLimit)).ToList();

    /// <summary>How many uploads are in progress, for Diagnostics.</summary>
    public int InProgress => _sessions.Values.Count(s => !s.Ended);
}
