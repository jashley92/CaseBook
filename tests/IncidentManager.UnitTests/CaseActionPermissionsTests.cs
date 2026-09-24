using System.Reflection;
using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// F-21: guards the write-authorization backstop. The map in <see cref="CaseActionPermissions"/> is the one
/// reviewed source of truth for which permission each <see cref="CaseService"/> mutation requires; these
/// tests keep it honest so a newly added write can never ship unguarded (the service fails closed, but a
/// forgotten entry would surface as a runtime error only when exercised — this catches it at build time).
/// </summary>
public sealed class CaseActionPermissionsTests
{
    /// <summary>
    /// The read-only use cases on <see cref="CaseService"/> — deliberately absent from the permission map,
    /// because their access is governed by need-to-know data scoping in the query layer, not action authz.
    /// Kept explicit so a genuinely new <em>mutation</em> that forgets a map entry fails this test instead of
    /// being silently waved through.
    /// </summary>
    private static readonly HashSet<string> ReadOnlyActions = new(StringComparer.Ordinal)
    {
        nameof(CaseService.CanViewAsync),
        nameof(CaseService.GetRestrictedClearanceRolesAsync),
        nameof(CaseService.IsCaseNumberAvailableAsync),
        nameof(CaseService.ListAsync),
        nameof(CaseService.GetDetailAsync),
        nameof(CaseService.ListActiveDataElementsAsync),
        nameof(CaseService.DataElementLabelsAsync),
        nameof(CaseService.EvaluateGateAsync),
        nameof(CaseService.FindEntityOverlapsAsync),
        nameof(CaseService.FindOpenCaseMatchesForIocsAsync),
        nameof(CaseService.FindRelatedOpenCasesAsync),
        nameof(CaseService.GetCaseLinksAsync),
        nameof(CaseService.SearchLinkableCasesAsync),
        nameof(CaseService.GetEntityLabelsAsync),
    };

    private static IEnumerable<string> PublicUseCaseMethods() =>
        typeof(CaseService)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => !m.IsSpecialName) // exclude property accessors
            .Where(m => typeof(Task).IsAssignableFrom(m.ReturnType)) // every use case is async
            .Select(m => m.Name)
            .Distinct();

    [Fact]
    public void Every_use_case_is_either_permission_mapped_or_explicitly_read_only()
    {
        foreach (var method in PublicUseCaseMethods())
        {
            var mapped = CaseActionPermissions.Required.ContainsKey(method);
            var readOnly = ReadOnlyActions.Contains(method);
            (mapped ^ readOnly).Should().BeTrue(
                $"CaseService.{method} must be in exactly one of the permission map or the read-only allowlist " +
                $"(mapped={mapped}, readOnly={readOnly}). A new mutation needs a CaseActionPermissions entry.");
        }
    }

    [Fact]
    public void Map_keys_all_resolve_to_a_real_mutating_method()
    {
        var methods = PublicUseCaseMethods().ToHashSet(StringComparer.Ordinal);
        foreach (var key in CaseActionPermissions.Required.Keys)
            methods.Should().Contain(key,
                $"permission map key '{key}' has no matching CaseService method (stale entry).");
    }

    [Fact]
    public void Map_values_are_defined_permissions()
    {
        foreach (var perm in CaseActionPermissions.Required.Values)
            Enum.IsDefined(perm).Should().BeTrue();
    }

    [Theory]
    [InlineData(nameof(CaseService.ReclassifyAsync), Permission.ChangeClassification)]
    [InlineData(nameof(CaseService.ReferToLegalAsync), Permission.ManageLegal)]
    [InlineData(nameof(CaseService.SetLegalHoldAsync), Permission.ManageLegal)]
    [InlineData(nameof(CaseService.SetArchivedAsync), Permission.Administer)]
    [InlineData(nameof(CaseService.RecordMaterialityAsync), Permission.EditCases)]
    [InlineData(nameof(CaseService.UpdateDetailsAsync), Permission.EditCases)]
    [InlineData(nameof(CaseService.AddNoteAsync), Permission.EditCases)]
    public void Key_actions_require_the_expected_permission(string action, Permission expected)
    {
        CaseActionPermissions.Required[action].Should().Be(expected);
    }
}
