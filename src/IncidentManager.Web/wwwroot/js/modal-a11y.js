// Modal focus management (UX-01). Blazor renders the .modal.d-block dialogs conditionally; when one
// is open the workspace calls imModal.arm(), and imModal.release() once it closes. arm() finds the
// visible trap modal, moves focus into it, and keeps Tab cycling within it; release() restores focus
// to whatever was focused before the modal opened. Loaded as an external file so it satisfies the
// strict CSP that blocks inline handlers. Escape-to-close is handled by Blazor (@onkeydown).
window.imModal = (function () {
    'use strict';

    var FOCUSABLE = [
        'a[href]', 'button:not([disabled])', 'input:not([disabled])',
        'select:not([disabled])', 'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])'
    ].join(',');

    var trapped = null;        // the modal element currently trapping focus
    var lastFocused = null;    // element to restore focus to on release
    var returnSel = null;      // explicit return-focus selector (data-return-focus), if set

    function focusables(el) {
        return Array.prototype.filter.call(el.querySelectorAll(FOCUSABLE), function (n) {
            // visible only: offsetParent is null for display:none / detached nodes
            return n.offsetParent !== null || n === document.activeElement;
        });
    }

    function onKeydown(e) {
        if (!trapped || e.key !== 'Tab') return;
        var f = focusables(trapped);
        if (f.length === 0) { e.preventDefault(); try { trapped.focus(); } catch (_) {} return; }
        var first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }

    function detach() {
        if (trapped) { document.removeEventListener('keydown', onKeydown, true); trapped = null; }
    }

    return {
        // Move focus into the visible trap modal and start cycling Tab within it.
        arm: function () {
            var el = document.querySelector('.modal.d-block.im-trap');
            if (!el || el === trapped) return;
            if (trapped) {
                detach();                       // switching from one modal to another: keep lastFocused
            } else {
                lastFocused = document.activeElement;
            }
            trapped = el;
            // A modal launched from a transient control (e.g. a dropdown item that unmounts when the
            // menu closes) can declare a stable element to return focus to when it closes.
            returnSel = el.getAttribute('data-return-focus') || null;
            document.addEventListener('keydown', onKeydown, true);
            // Prefer the first focusable inside the body (an input), else any focusable, else the box.
            var body = el.querySelector('.modal-body');
            var target = (body && focusables(body)[0]) || focusables(el)[0] || el;
            try { target.focus(); } catch (_) {}
        },
        // Stop trapping and return focus: prefer the declared return target, else whatever was focused
        // before the modal opened (if it's still in the DOM).
        release: function () {
            if (!trapped) return;
            detach();
            var back = lastFocused;
            var sel = returnSel;
            lastFocused = null;
            returnSel = null;
            var target = (sel && document.querySelector(sel)) ||
                         (back && document.contains(back) ? back : null);
            if (target) { try { target.focus(); } catch (_) {} }
        }
    };
})();
