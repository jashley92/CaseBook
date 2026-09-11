// Case-workspace keyboard shortcuts (U-14). CSP-safe: one delegated keydown listener from this external
// file, forwarded to the open CaseWorkspace Blazor component, which owns all behaviour. Bare digit 1..8
// switches tabs; 'n' focuses the note composer. Suppressed while typing (inputs/textarea/editor keep their
// own keys) and while a global 'g …' go-to sequence is in flight (that belongs to imHotkeys). Registration
// is idempotent so a circuit reconnect can't stack duplicate listeners; the listener stays attached but
// inert once the case page unregisters (dotnet == null).
window.imCaseHotkeys = (function () {
    let dotnet = null;
    let attached = false;
    let gPending = false;       // true briefly after 'g', so we defer the 'g …' sequence to imHotkeys
    let gTimer = null;

    function isTyping(el) {
        if (!el) return false;
        if (el.isContentEditable) return true;
        const tag = el.tagName;
        return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
    }

    function clearG() {
        gPending = false;
        if (gTimer) { clearTimeout(gTimer); gTimer = null; }
    }

    function send(name) {
        if (dotnet) { try { dotnet.invokeMethodAsync('OnCaseHotkey', name); } catch (e) { /* circuit gone */ } }
    }

    function onKeydown(e) {
        if (!dotnet) return;
        if (e.ctrlKey || e.metaKey || e.altKey) { clearG(); return; }
        if (isTyping(e.target)) { clearG(); return; }

        // Second key of a global 'g …' go-to sequence — leave it entirely to imHotkeys.
        if (gPending) { clearG(); return; }
        if (e.key === 'g') { gPending = true; gTimer = setTimeout(clearG, 1200); return; }

        if (e.key >= '1' && e.key <= '8') { e.preventDefault(); send('tab:' + e.key); return; }
        if (e.key === 'n' || e.key === 'N') { e.preventDefault(); send('note'); return; }
    }

    return {
        register: function (ref) {
            dotnet = ref;
            if (!attached) {
                document.addEventListener('keydown', onKeydown, true); // capture, like imHotkeys
                attached = true;
            }
        },
        unregister: function () {
            dotnet = null;
            clearG();
        }
    };
})();
