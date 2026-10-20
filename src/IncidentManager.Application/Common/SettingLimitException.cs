namespace IncidentManager.Application.Common;

/// <summary>
/// A refusal caused by an administrator's setting (the largest evidence file, the evidence storage limit, the free space
/// to keep): its message is for the person refused, and <see cref="SettingKey"/> names the setting, so a page can link an
/// administrator to where it's changed. An <see cref="ArgumentException"/>, so it's handled as any refusal is.
/// </summary>
public sealed class SettingLimitException(string message, string settingKey) : ArgumentException(message)
{
    public string SettingKey { get; } = settingKey;
}
