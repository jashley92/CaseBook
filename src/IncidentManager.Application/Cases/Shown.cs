namespace IncidentManager.Application.Cases;

/// <summary>
/// BUG-594: the value a page showed for a field when the user acted on it, so the save can be refused when someone changed
/// it meanwhile. A parameter of type <c>Shown&lt;T&gt;?</c> reads three ways: not given (null, the old call shape: no
/// check), <c>Shown.Of(null)</c> (the page showed none), or <c>Shown.Of(value)</c>.
/// </summary>
public readonly record struct Shown<T>(T Value);

/// <summary>BUG-594: makes a <see cref="Shown{T}"/>.</summary>
public static class Shown
{
    public static Shown<T> Of<T>(T value) => new(value);
}
