using System.Net.Http.Headers;
using System.Text.Json;
using IncidentManager.Application.Updates;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Updates;

/// <summary>
/// The update check (PROD-49), bound to <c>Updates</c>. <see cref="CheckEnabled"/> and <see cref="CheckIntervalHours"/>
/// are administrable (Settings › Updates); <see cref="Repository"/> and <see cref="Proxy"/> are server-side only.
/// </summary>
public sealed class UpdateCheckOptions
{
    /// <summary>Off by default: many SOC servers have no outbound internet, and the call is the organization's choice.</summary>
    public bool CheckEnabled { get; set; }

    /// <summary>Hours between checks (at least 6). Default 24.</summary>
    public int CheckIntervalHours { get; set; } = 24;

    /// <summary>The GitHub repository whose releases are checked, "owner/name".</summary>
    public string Repository { get; set; } = "jashley92/CaseBook";

    /// <summary>An outbound proxy for the check (e.g. "http://proxy.contoso.local:8080"). Read at start-up.</summary>
    public string? Proxy { get; set; }
}

public enum UpdateState
{
    /// <summary>The check is turned off.</summary>
    Disabled,
    /// <summary>A local build with no release version: nothing to compare.</summary>
    DevBuild,
    /// <summary>On, but not checked yet (the first check runs a couple of minutes after start).</summary>
    NotChecked,
    UpToDate,
    Available,
    /// <summary>The last check failed; <see cref="UpdateStatus.Problem"/> says why.</summary>
    Failed
}

/// <param name="Releases">Every published release newer than the running one, newest first.</param>
public sealed record UpdateStatus(
    UpdateState State, Version? Running, DateTimeOffset? CheckedAtUtc, IReadOnlyList<AvailableRelease> Releases,
    string? Problem)
{
    public AvailableRelease? Latest => Releases.Count > 0 ? Releases[0] : null;
}

/// <summary>
/// Asks GitHub which CaseBook releases are newer than this one, and keeps the answer in memory for Administration ›
/// Updates and the Administration nav dot. One anonymous GET to the public Releases API: nothing about this
/// installation is sent. It never blocks start-up or a page; a failure is shown as "couldn't check" and logged once
/// until the reason changes.
/// </summary>
public sealed class UpdateCheckService : IDisposable
{
    // A manual "Check now" more often than this returns the last answer (the anonymous API allows 60 calls an hour).
    private static readonly TimeSpan ManualThrottle = TimeSpan.FromMinutes(1);
    private const int MaxResponseBytes = 4 * 1024 * 1024;

    private readonly IHttpClientFactory _http;
    private readonly IOptionsMonitor<UpdateCheckOptions> _options;
    private readonly ILogger<UpdateCheckService> _logger;
    private readonly TimeProvider _time;
    private readonly Version? _running;
    private readonly bool _releaseBuild;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private UpdateStatus? _last;
    private DateTimeOffset _lastAttemptUtc = DateTimeOffset.MinValue;
    private string? _loggedProblem;
    private string? _loggedLatest;

    public UpdateCheckService(IHttpClientFactory http, IOptionsMonitor<UpdateCheckOptions> options,
        ILogger<UpdateCheckService> logger, TimeProvider? time = null, Version? running = null)
    {
        _http = http;
        _options = options;
        _logger = logger;
        _time = time ?? TimeProvider.System;
        _running = running ?? AppVersionInfo.Current;
        _releaseBuild = AppVersionInfo.IsRelease(_running);
    }

    /// <summary>Raised after each check, so an open page can redraw.</summary>
    public event Action? Changed;

    /// <summary>The last answer, or why there isn't one.</summary>
    public UpdateStatus Status
    {
        get
        {
            if (!_options.CurrentValue.CheckEnabled) return new(UpdateState.Disabled, _running, null, [], null);
            if (!_releaseBuild || _running is null) return new(UpdateState.DevBuild, _running, null, [], null);
            return _last ?? new(UpdateState.NotChecked, _running, null, [], null);
        }
    }

    /// <summary>True when the check is on and has found a newer release.</summary>
    public bool UpdateAvailable => Status.State == UpdateState.Available;

    /// <summary>
    /// Checks now. A <paramref name="manual"/> check within a minute of the last one returns that answer instead.
    /// Never throws, except for cancellation.
    /// </summary>
    public async Task<UpdateStatus> CheckAsync(bool manual = false, CancellationToken ct = default)
    {
        var o = _options.CurrentValue;
        if (!o.CheckEnabled || !_releaseBuild || _running is null) return Status;

        await _gate.WaitAsync(ct);
        try
        {
            var now = _time.GetUtcNow();
            if (manual && _last is not null && now - _lastAttemptUtc < ManualThrottle) return Status;
            _lastAttemptUtc = now;
            _last = await FetchAsync(o, _running, now, ct);
        }
        finally { _gate.Release(); }

        LogOnce(_last);
        Changed?.Invoke();
        return Status;
    }

    private async Task<UpdateStatus> FetchAsync(UpdateCheckOptions o, Version running, DateTimeOffset now, CancellationToken ct)
    {
        UpdateStatus Failed(string why) => new(UpdateState.Failed, running, now, _last?.Releases ?? [], why);

        if (!ReleaseFeed.IsRepository(o.Repository)) return Failed("the repository setting isn't owner/name");
        try
        {
            using var client = _http.CreateClient("updates");
            client.Timeout = TimeSpan.FromSeconds(10);
            client.MaxResponseContentBufferSize = MaxResponseBytes;
            using var request = new HttpRequestMessage(HttpMethod.Get, ReleaseFeed.ApiUri(o.Repository));
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("CaseBook", running.ToString(3)));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");

            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
                return Failed((int)response.StatusCode is 403 or 429
                    ? $"GitHub refused the request ({(int)response.StatusCode}); it may be rate-limiting this address"
                    : $"GitHub answered {(int)response.StatusCode}");

            var json = await response.Content.ReadAsStringAsync(ct);
            var newer = ReleaseFeed.Newer(json, o.Repository, running);
            return new(newer.Count > 0 ? UpdateState.Available : UpdateState.UpToDate, running, now, newer, null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (TaskCanceledException) { return Failed("no answer within 10 seconds"); }
        catch (HttpRequestException ex) { return Failed($"couldn't reach GitHub ({ex.HttpRequestError})"); }
        catch (JsonException) { return Failed("the answer wasn't a list of releases"); }
        catch (Exception ex) when (ex is InvalidOperationException or IOException)
        {
            return Failed("couldn't read the answer");
        }
    }

    public void Dispose() => _gate.Dispose();

    // A failing check is logged once, not every day, until it starts failing for a different reason or succeeds; a new
    // release is logged once.
    private void LogOnce(UpdateStatus s)
    {
        if (s.State == UpdateState.Failed)
        {
            if (s.Problem != _loggedProblem) _logger.LogWarning("Update check failed: {Problem}.", s.Problem);
            _loggedProblem = s.Problem;
            return;
        }
        if (_loggedProblem is not null) _logger.LogInformation("Update check is working again.");
        _loggedProblem = null;
        if (s.Latest is { } latest && latest.Tag != _loggedLatest)
            _logger.LogInformation("CaseBook {Latest} is available (running {Running}).", latest.Tag, s.Running?.ToString(3));
        _loggedLatest = s.Latest?.Tag;
    }
}
