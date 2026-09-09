namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Signals that administered operational settings changed so any layered configuration (the DB
/// settings provider) can re-read them and consumers bound via <c>IOptionsMonitor</c> observe the
/// new values without a restart. Implemented in Infrastructure over <c>IConfigurationRoot.Reload()</c>.
/// </summary>
public interface ISettingsReloader
{
    void Reload();
}
