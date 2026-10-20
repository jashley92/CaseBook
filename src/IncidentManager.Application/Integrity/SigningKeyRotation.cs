namespace IncidentManager.Application.Integrity;

/// <summary>
/// The reminder to rotate the seal-signing key (OPERATIONS.md section 2): due once the key has signed seals for
/// <see cref="SettingKey"/> days, counted from its first seal. Rotation itself stays the administrator's (ADR 0016).
/// </summary>
public static class SigningKeyRotation
{
    public const string SettingKey = "Integrity:RotationReminderDays";
    public const int DefaultDays = 365;
    public const int MaxDays = 3650;

    /// <summary>The interval, kept within 0 (off) to <see cref="MaxDays"/>.</summary>
    public static int Clamp(int days) => Math.Clamp(days, 0, MaxDays);

    /// <summary>When the key is due for rotation, or null when the reminder is off or the key has signed nothing yet.</summary>
    public static DateTimeOffset? DueAt(DateTimeOffset? firstSealed, int days) =>
        days > 0 && firstSealed is { } first ? Common.Instants.AddClamped(first, TimeSpan.FromDays(days)) : null;
}
