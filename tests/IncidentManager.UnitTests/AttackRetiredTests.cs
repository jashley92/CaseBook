using IncidentManager.Application.Mitre;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>Ids ATT&amp;CK revoked or deprecated: where each went, and the tactic a replaced tag moves to.</summary>
public class AttackRetiredTests
{
    [Fact]
    public void A_revoked_id_names_the_live_technique_that_replaced_it()
    {
        var gone = AttackCatalog.Retired(" t1574.002 ");
        Assert.NotNull(gone);
        Assert.Equal("T1574.002", gone.Id);
        Assert.Equal("DLL Side-Loading", gone.Name);
        Assert.Equal("T1574.001", gone.ReplacedBy?.Id);
        Assert.Equal("T1574.002 (DLL Side-Loading) is no longer in ATT&CK v19.1: it was replaced by T1574.001 DLL.", AttackCatalog.RetiredText(gone));
    }

    [Fact]
    public void A_deprecated_id_says_it_has_no_replacement()
    {
        var gone = AttackCatalog.Retired("T1026");
        Assert.NotNull(gone);
        Assert.Null(gone.ReplacedBy);
        Assert.EndsWith("deprecated with no replacement.", AttackCatalog.RetiredText(gone));
    }

    [Theory]
    [InlineData("T1566.001")] // live
    [InlineData("T9999")]     // never in ATT&CK
    [InlineData("")]
    [InlineData(null)]
    public void Live_unknown_and_empty_ids_are_not_retired(string? id) => Assert.Null(AttackCatalog.Retired(id));

    [Fact]
    public void Every_retired_id_is_out_of_the_catalog_and_most_have_a_replacement()
    {
        // The list is generated with the catalog from one bundle: none of its ids is live, every replacement is.
        var all = new[] { "T1002", "T1004", "T1574.002", "T1026" }.Select(AttackCatalog.Retired).ToList();
        Assert.All(all, r => Assert.NotNull(r));
        Assert.All(all, r => Assert.Null(AttackCatalog.Find(r!.Id)));
        Assert.All(all.Where(r => r!.ReplacedBy is not null), r => Assert.NotNull(AttackCatalog.Find(r!.ReplacedBy!.Id)));
    }

    [Fact]
    public void A_replaced_tag_keeps_its_tactic_when_the_replacement_has_it_else_takes_the_primary()
    {
        var dll = AttackCatalog.Find("T1574.001")!;
        Assert.Equal(MitreTactic.Stealth, AttackCatalog.ReplacementTactic(dll, MitreTactic.Stealth));
        Assert.Equal(dll.PrimaryTactic, AttackCatalog.ReplacementTactic(dll, MitreTactic.Persistence));
        Assert.Contains(AttackCatalog.ReplacementTactic(dll, MitreTactic.Persistence), dll.Tactics);
    }
}
