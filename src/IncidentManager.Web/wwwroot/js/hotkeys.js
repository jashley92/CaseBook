// Global keyboard-shortcut dispatcher (U-22 / U-14 light chords). CSP-safe: a single delegated
// keydown listener attached from this external file (no inline handlers). It never acts on its own —
// it just recognises chords and forwards them to the CommandPalette Blazor component, which owns all
// behaviour. Registration is idempotent so a circuit reconnect can't stack duplicate listeners.
window.imHotkeys = (function () {
    let dotnet = null;          // DotNetObjectReference to the CommandPalette component
    let attached = false;
    let leader = false;         // true after 'g' is pressed, waiting for the second key of a sequence
    let leaderTimer = null;

    // Fields, textareas, selects and rich-text editors must keep their own keys — the single-key
    // chords (g, /, ?) are suppressed while the caret is in one of them. Ctrl/Cmd-K and Escape still
    // work everywhere so the palette is always reachable.
    function isTyping(el) {
        if (!el) return false;
        if (el.isContentEditable) return true;
        const tag = el.tagName;
        return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
    }

    function clearLeader() {
        leader = false;
        if (leaderTimer) { clearTimeout(leaderTimer); leaderTimer = null; }
    }

    function send(name) {
        if (dotnet) { try { dotnet.invokeMethodAsync('OnHotkey', name); } catch (e) { /* circuit gone */ } }
    }

    function onKeydown(e) {
        if (!dotnet) return;

        // Command palette — reachable from anywhere, including while typing.
        if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
            e.preventDefault();
            clearLeader();
            send('palette');
            return;
        }

        // Let the component dismiss whatever overlay is open. Don't preventDefault so native
        // behaviour (blur, close) still happens if nothing is open.
        if (e.key === 'Escape') {
            clearLeader();
            send('escape');
            return;
        }

        // Everything below is a bare single-key chord: ignore it with modifiers or while typing.
        if (isTyping(e.target) || e.ctrlKey || e.metaKey || e.altKey) { clearLeader(); return; }

        // Second key of a 'g …' go-to sequence.
        if (leader) {
            const k = (e.key || '').toLowerCase();
            clearLeader();
            if (k === 'd' || k === 'm' || k === 'c' || k === 'n' || k === 'i') {
                e.preventDefault();
                send('go:' + k);
            }
            return;
        }

        if (e.key === 'g') {
            leader = true;
            leaderTimer = setTimeout(clearLeader, 1200); // abandon a half-typed sequence
            return;
        }
        if (e.key === '/') { e.preventDefault(); send('palette'); return; }
        if (e.key === '?') { e.preventDefault(); send('help'); return; }
    }

    return {
        register: function (ref) {
            dotnet = ref;
            if (!attached) {
                // Capture phase so the chords are seen even if a child stops propagation.
                document.addEventListener('keydown', onKeydown, true);
                attached = true;
            }
        },
        unregister: function () {
            dotnet = null;
            clearLeader();
            // Leave the listener attached but inert (dotnet == null) — cheaper than churn across
            // reconnects, and it does nothing without a live reference.
        }
    };
})();
