using IncidentManager.Application.Abstractions;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// BUG-100: reads <c>Notifications:ExerciseEscalation</c> from the live configuration on each use, so an administered
/// change applies without a restart. Anything but "Skip" tags.
/// </summary>
public sealed class ConfigurationExerciseEscalationPolicy(IConfiguration config) : IExerciseEscalationPolicy
{
    public const string Key = "Notifications:ExerciseEscalation";

    public ExerciseEscalation Mode =>
        string.Equals(config[Key]?.Trim(), nameof(ExerciseEscalation.Skip), StringComparison.OrdinalIgnoreCase)
            ? ExerciseEscalation.Skip
            : ExerciseEscalation.Tag;
}
