using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Application.StageGates;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Components.Pages.CaseTabs;
using IncidentManager.Web.Components.Pages.Workspace;
using IncidentManager.Web.Components.Shared;
using IncidentManager.Web.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Routing;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.JSInterop;

namespace IncidentManager.Web.Components.Pages;

/// <summary>
/// RD-27: the case's one-click acts (assign to me, legal hold, archive, pin), the screenshot preview, and the same acts
/// offered in the command palette (PROD-19).
/// </summary>
public partial class CaseWorkspace
{
    // Quick self-assign from the Actions menu — picks the case up as an Analyst without opening the modal.
    // Self-assignments never notify (the notifier skips assignee == assigner).
    private async Task AssignToMe()
    {
        try
        {
            await Cases.AssignAsync(Id, _myId ?? CurrentUser.UserId, CurrentUser.DisplayName, CaseAssignmentRole.Analyst);
            await Reload();
            Toasts.Success("Assigned to you.");
        }
        catch (ForbiddenException)
        {
            OnForbidden(); // REL-08
            Toasts.Error(PermissionLostMessage);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            Toasts.Error(ex.Message);
        }
    }


    private async Task OpenShot(Guid evidenceId)
    {
        _previewShotId = evidenceId;
        // PROD-13: opening the preview is a deliberate look at the evidence, so it lands in the chain of custody
        // as "Viewed" (the thumbnails that load on their own never do). Best-effort: a failed write must not
        // stop the person seeing the image.
        try { await EvidenceSvc.RecordViewedAsync(evidenceId); }
        catch (Exception ex) when (ex is InvalidOperationException or Microsoft.EntityFrameworkCore.DbUpdateException) { }
    }
    private void CloseShot() => _previewShotId = null;


    private async Task SetLegalHold(bool held)
    {
        _retentionMsg = null;
        try
        {
            await Cases.SetLegalHoldAsync(Id, held, reason: null);
            await Reload();
            Toasts.Success(held ? "Legal hold placed" : "Legal hold released");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or ForbiddenException)
        {
            Toasts.Error(ex.Message);
        }
    }

    private async Task SetArchived(bool archived)
    {
        _retentionMsg = null;
        try
        {
            await Cases.SetArchivedAsync(Id, archived);
            await Reload();
            Toasts.Success(archived ? "Case archived" : "Case restored");
        }
        catch (Exception ex) when (ex is InvalidOperationException or ForbiddenException)
        {
            _retentionMsg = ex.Message;
        }
    }

    // --- PROD-19: the case's action verbs, surfaced in the command palette -----------------------------
    // Mirrors the Actions dropdown + the stepper's Advance button, reusing the same permission gates and the
    // same handlers (so behaviour and audit are identical whether invoked by mouse or by Ctrl/⌘K). Recomputed
    // on demand from live state; the palette closes itself before invoking Run.
    private IReadOnlyList<IncidentManager.Web.Services.CasePaletteAction> BuildPaletteActions()
    {
        var list = new List<IncidentManager.Web.Services.CasePaletteAction>();
        if (_case is null) return list;

        // Assign to me — one-click self-assign, only when editable and not already on the case.
        if (_canEdit && !_case.Assignments.Any(a => string.Equals(a.UserId, _myId, StringComparison.OrdinalIgnoreCase)))
            list.Add(new("Assign to me", "bi-person-check", RunThenRender(AssignToMe)));

        // Advance to the next phase (Close routes through the gated status modal — see AdvanceTo).
        if (_canEdit && NextPhase() is { } np)
            list.Add(new($"Advance to {Ui.Label(np)}", "bi-arrow-right-circle", RunThenRender(() => AdvanceTo(np))));

        if (_canReclassify)
            list.Add(new(_case.Classification is null ? "Promote onto the ladder…" : "Reclassify…",
                "bi-diagram-2", () => OpenModalFromPalette("reclass")));

        if (_canEdit)
        {
            list.Add(new("Change severity…", "bi-thermometer-half", () => OpenModalFromPalette("severity")));
            list.Add(new("Change phase…", "bi-signpost-split", () => OpenModalFromPalette("status")));
            list.Add(new("Refer to Legal / Privacy…", "bi-briefcase", () => OpenModalFromPalette("legal")));
            if (_case.Classification is Classification.Incident or Classification.Breach)
                list.Add(new("Record materiality determination…", "bi-clipboard2-check", () => OpenModalFromPalette("materiality")));
            list.Add(new("Assign someone to this case…", "bi-person-plus", () => OpenModalFromPalette("assign")));
            if (_case.Phase == CasePhase.Closed)
                list.Add(new("Reopen case…", "bi-arrow-counterclockwise", () => OpenModalFromPalette("reopen")));
        }

        if (_canEdit && _case.Phase != CasePhase.Closed)
            list.Add(new("Supersede as a duplicate…", "bi-files", () => OpenModalFromPalette("supersede")));
        if (_canEdit && !_case.IsRestricted)
            list.Add(new("Restrict to need-to-know…", "bi-lock", () => OpenModalFromPalette("restrict")));
        else if (_canEdit && CanLiftRestriction)
            list.Add(new("Lift restriction…", "bi-unlock", () => OpenModalFromPalette("unrestrict")));

        if (_canManageLegal)
        {
            if (_case.LegalHold && Cases.LegalHoldReleaseNeedsSecondApprover)
            {
                if (!_case.LegalHoldReleasePending)
                    list.Add(new("Request legal hold release…", "bi-unlock", () => OpenModalFromPalette("holdrelease")));
            }
            else
            {
                list.Add(_case.LegalHold
                    ? new("Release legal hold…", "bi-unlock", () => OpenModalFromPalette("holdrelease"))
                    : new("Place legal hold", "bi-lock", RunThenRender(() => SetLegalHold(true))));
            }
        }

        if (_canAdmin)
        {
            if (_case.IsArchived)
                list.Add(new("Restore from archive", "bi-box-arrow-up", RunThenRender(() => SetArchived(false))));
            else
                list.Add(new("Archive case…", "bi-archive", () => OpenModalFromPalette("archive")));
        }

        // Always available (any viewer): pin/unpin (PROD-20) and copy link — dependable, personal actions.
        list.Add(new(_isPinned ? "Unpin this case" : "Pin this case",
            _isPinned ? "bi-pin-angle-fill" : "bi-pin-angle", RunThenRender(TogglePin)));
        list.Add(new("Copy link to this case", "bi-link-45deg", CopyCaseLink));

        return list;
    }

    // PROD-20: pin/unpin the open case for the current user.
    private bool _isPinned;

    private async Task TogglePin()
    {
        try
        {
            _isPinned = await Shortcuts.TogglePinAsync(Id);
            await OpenTabs.RefreshAsync();   // RD-21: a pinned case is a tab that stays
            Toasts.Success(_isPinned ? "Pinned for quick access." : "Unpinned.");
        }
        catch (InvalidOperationException ex)
        {
            Toasts.Error(ex.Message);
        }
    }

    // A one-click action invoked from the palette: run it, then re-render this workspace (the palette has
    // already closed itself). Wrapped so the private handlers keep their existing signatures.
    private Func<Task> RunThenRender(Func<Task> action) => async () =>
    {
        await action();
        StateHasChanged();
    };

    // Opening a modal from the palette is async (it may load the stage gate), and needs an explicit re-render
    // because the trigger lives in another component's event handler, not this one's.
    private async Task OpenModalFromPalette(string name)
    {
        await OpenModal(name);
        StateHasChanged();
    }

    private async Task CopyCaseLink()
    {
        var url = Nav.ToAbsoluteUri($"cases/{Id}").ToString();
        try
        {
            await JS.InvokeVoidAsync("navigator.clipboard.writeText", url);
            Toasts.Success("Case link copied.");
        }
        catch
        {
            // Clipboard API unavailable (insecure context / permissions) — surface the URL so it's still usable.
            Toasts.Info(url);
        }
    }
}
