namespace IncidentManager.Web.Services;

/// <summary>Whether on-screen absolute timestamps render in UTC or the viewer's local time zone.</summary>
public enum TimeDisplayMode { Utc, Local }

/// <summary>
/// Circuit-scoped display preference for on-screen timestamps (U-29). This affects <em>rendering only</em>:
/// stored data stays UTC, and forensic artifacts (reports, exports, the compliance bundle, the stored
/// audit trail) always remain UTC so evidence is unambiguous. Every stamp this service produces carries an
/// explicit zone label (e.g. "UTC", "UTC-04:00"), so a value is never ambiguous whichever mode is active.
/// The mode is persisted in the browser (localStorage) and the zone is detected from the browser; both are
/// pushed in once per circuit by <c>TimeSetup</c>.
/// </summary>
public sealed class TimeDisplay
{
    private TimeZoneInfo _zone = TimeZoneInfo.Utc;

    /// <summary>Active display mode. Defaults to UTC until the circuit is configured from the browser.</summary>
    public TimeDisplayMode Mode { get; private set; } = TimeDisplayMode.Utc;

    /// <summary>True once the browser preference/zone has been read for this circuit (guards re-init on refresh).</summary>
    public bool Initialized { get; private set; }

    /// <summary>Raised when the mode or zone changes, so the layout can re-render every visible timestamp.</summary>
    public event Action? Changed;

    /// <summary>The IANA id the browser reported (e.g. "America/New_York"), or null if unknown/not yet detected.</summary>
    public string? BrowserZoneId { get; private set; }

    /// <summary>The zone timestamps are shown in: the browser zone when Mode=Local and it resolved, else UTC.</summary>
    public TimeZoneInfo Zone => Mode == TimeDisplayMode.Local ? _zone : TimeZoneInfo.Utc;

    /// <summary>Push the browser-detected zone and stored mode into this circuit.</summary>
    public void Configure(string? ianaZoneId, TimeDisplayMode mode)
    {
        BrowserZoneId = ianaZoneId;
        _zone = Resolve(ianaZoneId);
        Mode = mode;
        Initialized = true;
        Changed?.Invoke();
    }

    /// <summary>Flip the display mode (the zone stays whatever was last detected).</summary>
    public void SetMode(TimeDisplayMode mode)
    {
        Mode = mode;
        Initialized = true;
        Changed?.Invoke();
    }

    private static TimeZoneInfo Resolve(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return TimeZoneInfo.Utc;
        // .NET 6+ resolves IANA ids on every platform via ICU. Fall back to UTC for anything unrecognised.
        try { return TimeZoneInfo.FindSystemTimeZoneById(id!); }
        catch { return TimeZoneInfo.Utc; }
    }

    private DateTimeOffset ToZone(DateTimeOffset ts) => TimeZoneInfo.ConvertTime(ts, Zone);

    // A per-timestamp offset label (honours DST for the specific instant), e.g. "UTC", "UTC-04:00".
    private static string OffsetLabel(TimeSpan offset)
    {
        if (offset == TimeSpan.Zero) return "UTC";
        var sign = offset < TimeSpan.Zero ? "-" : "+";
        var a = offset.Duration();
        return $"UTC{sign}{a.Hours:D2}:{a.Minutes:D2}";
    }

    /// <summary>The active zone label at the current moment (e.g. "UTC", "UTC-04:00") — for column headers.</summary>
    public string Label => OffsetLabel(ToZone(DateTimeOffset.UtcNow).Offset);

    /// <summary>
    /// The viewer's detected local-zone offset label at the current moment (e.g. "UTC-04:00"), independent of
    /// the active display mode — so the "Local" option in the display toggle can be labelled even while UTC is
    /// active. Falls back to "UTC" when no browser zone was detected (local would then equal UTC anyway).
    /// </summary>
    public string LocalLabel => OffsetLabel(TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, _zone).Offset);

    /// <summary>Full stamp: date, time to the second, and an explicit zone label. Replaces the old ToString("u").</summary>
    public string Long(DateTimeOffset ts)
    {
        var z = ToZone(ts);
        return $"{z:yyyy-MM-dd HH:mm:ss} {OffsetLabel(z.Offset)}";
    }

    public string Long(DateTimeOffset? ts, string dash = "—") => ts is { } t ? Long(t) : dash;

    /// <summary>Compact stamp for dense rails: month/day, time to the minute, zone label.</summary>
    public string Short(DateTimeOffset ts)
    {
        var z = ToZone(ts);
        return $"{z:MMM d, HH:mm} {OffsetLabel(z.Offset)}";
    }

    /// <summary>Time of day only, with a zone label (e.g. "04:57 UTC") — for the dashboard "as of" line.</summary>
    public string TimeOnly(DateTimeOffset ts)
    {
        var z = ToZone(ts);
        return $"{z:HH:mm} {OffsetLabel(z.Offset)}";
    }

    /// <summary>Calendar date in the active zone (no time), for due dates and month labels.</summary>
    public string DateOnly(DateTimeOffset ts) => $"{ToZone(ts):yyyy-MM-dd}";

    public string DateOnly(DateTimeOffset? ts, string dash = "—") => ts is { } t ? DateOnly(t) : dash;
}
