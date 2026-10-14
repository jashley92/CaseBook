using System.Globalization;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace IncidentManager.Web.Components.Shared;

/// <summary>
/// BUG-408 / BUG-426: the shared body of <c>DateTimeInput</c>, <c>DateInput</c> and <c>TimeInput</c>. Blazor's own @bind
/// wrote the value back after every keystroke, which reset the segment being typed in a date, time or date-and-time
/// field; date-field.js reports changes instead and only ever writes a value the field isn't already showing.
/// Bound like an input (@bind-Value, with :after). Other attributes (id, class, aria-label, title, min, max, disabled)
/// pass through to the input.
/// </summary>
public abstract class DateFieldBase<TValue> : ComponentBase, IAsyncDisposable
{
    [Inject] private IJSRuntime JS { get; set; } = default!;

    [Parameter] public TValue? Value { get; set; }
    [Parameter] public EventCallback<TValue?> ValueChanged { get; set; }
    [Parameter(CaptureUnmatchedValues = true)] public IReadOnlyDictionary<string, object>? AdditionalAttributes { get; set; }

    protected static readonly bool IsNullable = Nullable.GetUnderlyingType(typeof(TValue)) is not null;
    protected static readonly Type Underlying = Nullable.GetUnderlyingType(typeof(TValue)) ?? typeof(TValue);

    /// <summary>The input's value format (its length is also how much of a reported value is read).</summary>
    protected abstract string Format { get; }
    /// <summary>The value types this field binds, for the error when it's bound to something else.</summary>
    protected abstract Type[] Supported { get; }
    protected abstract TValue FromText(DateTime parsed);
    protected abstract string Show(TValue? value);

    protected ElementReference Element { get; set; }
    private DotNetObjectReference<DateFieldBase<TValue>>? _self;
    // What the input was rendered with first. It never changes, so the render tree never writes the value again.
    protected string? FirstShown { get; private set; }
    // What the field shows now (as far as the server knows): set from the browser's reports and from Value.
    private string _shown = "";
    private bool _attached;

    protected override void OnInitialized()
    {
        if (!Supported.Contains(Underlying))
            throw new InvalidOperationException(
                $"{GetType().Name} binds {string.Join(", ", Supported.Select(t => t.Name))} (or a nullable one), not {typeof(TValue).Name}.");
        _shown = Show(Value);
        FirstShown = _shown;
    }

    protected override async Task OnParametersSetAsync()
    {
        var wanted = Show(Value);
        if (wanted == _shown) return;
        _shown = wanted;
        if (_attached)
        {
            try { await JS.InvokeVoidAsync("imDateField.set", Element, wanted); }
            catch (JSDisconnectedException) { }
            catch (JSException) { }
        }
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (!firstRender) return;
        _self = DotNetObjectReference.Create(this);
        try { await JS.InvokeVoidAsync("imDateField.attach", Element, _self, _shown); _attached = true; }
        catch (JSDisconnectedException) { }
        catch (JSException) { }
    }

    [JSInvokable]
    public async Task Changed(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            if (!IsNullable) { await Restore(); return; }   // a required value can't be emptied: show it again
            _shown = "";
            await ValueChanged.InvokeAsync(default);
            return;
        }
        if (!DateTime.TryParseExact(text.Length > Format.Length ? text[..Format.Length] : text, Format,
                CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
            return;
        var value = FromText(parsed);
        var shown = Show(value);
        // What the bound value had beyond what's shown (seconds, a time of day) is kept when the shown text didn't change.
        if (Show(Value) == shown) return;
        _shown = shown;
        await ValueChanged.InvokeAsync(value);
    }

    private async Task Restore()
    {
        try { await JS.InvokeVoidAsync("imDateField.set", Element, _shown); }
        catch (JSDisconnectedException) { }
        catch (JSException) { }
    }

    protected string Text(IFormattable value) => value.ToString(Format, CultureInfo.InvariantCulture);

    public async ValueTask DisposeAsync()
    {
        if (_attached)
        {
            try { await JS.InvokeVoidAsync("imDateField.detach", Element); }
            catch (JSDisconnectedException) { }
            catch (JSException) { }
        }
        _self?.Dispose();
        GC.SuppressFinalize(this);
    }
}
