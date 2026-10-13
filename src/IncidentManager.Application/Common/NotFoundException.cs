namespace IncidentManager.Application.Common;

/// <summary>
/// REV-64: the thing asked for isn't there, or isn't one the caller may see (need-to-know answers the same way, so a
/// restricted item's existence isn't given away). An <see cref="InvalidOperationException"/>, so callers that already
/// catch that keep working; an endpoint maps it to 404 rather than letting it surface as an unhandled 500.
/// </summary>
public sealed class NotFoundException(string message) : InvalidOperationException(message);
