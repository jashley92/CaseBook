using FluentAssertions;
using FluentValidation;
using FluentValidation.Results;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// REL-06: <see cref="UserFacingError.Describe"/> shows domain/validation/authorization messages verbatim
/// (they are authored for the user) and replaces cryptic internal failures (EF/SQLite/IO) with a generic
/// line so nothing internal leaks into the UI.
/// </summary>
public sealed class UserFacingErrorTests
{
    private static string Describe(Exception ex) =>
        UserFacingError.Describe(ex, NullLogger.Instance, "testing");

    [Fact]
    public void A_validation_exception_joins_its_messages()
    {
        var ex = new ValidationException(new[]
        {
            new ValidationFailure("Title", "Title is required."),
            new ValidationFailure("Severity", "Severity is invalid.")
        });

        Describe(ex).Should().Be("Title is required. Severity is invalid.");
    }

    [Fact]
    public void Domain_exception_messages_pass_through_verbatim()
    {
        Describe(new InvalidOperationException("Case number '2026-01' is already in use."))
            .Should().Be("Case number '2026-01' is already in use.");
        Describe(new ArgumentException("The detected time cannot be in the future."))
            .Should().Be("The detected time cannot be in the future.");
        Describe(new StaleEditException("stamp", "Another author changed this."))
            .Should().Be("Another author changed this.");
        Describe(new ForbiddenException(Permission.EditCases))
            .Should().Contain("permission");
    }

    [Fact]
    public void An_internal_exception_is_replaced_and_never_leaks_its_detail()
    {
        var ex = new DbUpdateException("SQLite Error 19: 'UNIQUE constraint failed: AuditLog.Sequence'.");

        var shown = Describe(ex);

        shown.Should().Be(UserFacingError.GenericSave);
        shown.Should().NotContain("SQLite");
        shown.Should().NotContain("constraint");
    }

    [Fact]
    public void The_caller_can_override_the_generic_fallback()
    {
        var shown = UserFacingError.Describe(new DbUpdateException("internal"),
            NullLogger.Instance, "uploading evidence", "The file couldn't be uploaded. Please try again.");

        shown.Should().Be("The file couldn't be uploaded. Please try again.");
    }
}
