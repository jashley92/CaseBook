namespace IncidentManager.Web.Services;

/// <summary>Severity/appearance of a toast.</summary>
public enum ToastLevel { Success, Info, Warning, Error }

/// <summary>A single transient notification.</summary>
public sealed record Toast(Guid Id, ToastLevel Level, string Message);

/// <summary>
/// Scoped (per-circuit) publisher of transient success/info toasts. CSP-safe — the
/// <c>ToastHost</c> component renders and auto-dismisses them entirely in Blazor/CSS,
/// with no inline script. Components call <see cref="Success"/> etc.; the host subscribes
/// to <see cref="OnChange"/>.
/// </summary>
public sealed class ToastService
{
    private readonly List<Toast> _toasts = new();

    public IReadOnlyList<Toast> Toasts => _toasts;

    /// <summary>Raised whenever the toast list changes (add or dismiss).</summary>
    public event Action? OnChange;

    public void Success(string message) => Show(ToastLevel.Success, message);
    public void Info(string message) => Show(ToastLevel.Info, message);
    public void Warning(string message) => Show(ToastLevel.Warning, message);
    public void Error(string message) => Show(ToastLevel.Error, message);

    public void Show(ToastLevel level, string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return;
        _toasts.Add(new Toast(Guid.NewGuid(), level, message));
        OnChange?.Invoke();
    }

    public void Dismiss(Guid id)
    {
        if (_toasts.RemoveAll(t => t.Id == id) > 0)
            OnChange?.Invoke();
    }
}
