// RD-24: CaseBook's one keyboard dispatcher (replaces hotkeys.js and case-hotkeys.js). CSP-safe: one delegated
// capture-phase keydown listener from this external file. It never acts on its own: it recognises the user's keys and
// forwards a command to the CommandPalette component (anywhere) or the open CaseWorkspace (case keys), which own all
// behaviour. The keys come from the server (Application/Preferences/Keymap.cs plus the user's own bindings) through
// configure(). Single-key shortcuts (no Ctrl or Alt, including "g" sequences) never fire while typing in a field, and
// are all off when the user switches them off (WCAG 2.1.4). Three keys are fixed so nobody can be locked out:
// Ctrl/Cmd+K (command bar), Esc (close) and Ctrl/Cmd+Enter (save what you're writing).
window.imKeymap = (function () {
    let globalRef = null;       // CommandPalette
    let caseRef = null;         // CaseWorkspace, while a case is open
    let attached = false;
    let singleOff = false;
    // binding -> { scope: 'any' | 'case', command }
    let bindings = new Map();
    let leader = false;
    let leaderTimer = null;

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

    // The palette opens through a server round trip, so keys typed straight after opening it would land on the page
    // before its input exists. Hold printable keys until the input appears, then hand them over. Gives up after 2 s.
    let buffering = false, buffer = '', bufferTimer = null;
    function stopBuffering() { buffering = false; buffer = ''; if (bufferTimer) { clearTimeout(bufferTimer); bufferTimer = null; } }
    function startBuffering() {
        stopBuffering();
        buffering = true;
        bufferTimer = setTimeout(stopBuffering, 2000);
        const started = Date.now();
        (function waitForInput() {
            if (!buffering) return;
            const input = document.querySelector('.cmdk-input');
            if (input) {
                input.focus();
                if (buffer) { input.value = buffer; input.dispatchEvent(new Event('input', { bubbles: true })); }
                stopBuffering();
                return;
            }
            if (Date.now() - started < 2000) requestAnimationFrame(waitForInput);
        })();
    }

    function sendGlobal(cmd) {
        if (globalRef) { try { globalRef.invokeMethodAsync('OnHotkey', cmd); } catch (e) { /* circuit gone */ } }
        if (cmd === 'palette') startBuffering();
    }
    function sendCase(cmd) {
        if (caseRef) { try { caseRef.invokeMethodAsync('OnCaseHotkey', cmd); } catch (e) { /* circuit gone */ } }
    }
    function run(b) {
        if (b.scope === 'case') { if (!caseRef) return false; sendCase(b.command); return true; }
        sendGlobal(b.command);
        return true;
    }

    // The binding name for a key press with modifiers: "Ctrl+Shift+F", "Alt+N".
    function chordName(e) {
        let key = e.key || '';
        if (key.length === 1) key = key.toUpperCase();
        const mods = [];
        if (e.ctrlKey || e.metaKey) mods.push('Ctrl');
        if (e.altKey) mods.push('Alt');
        if (e.shiftKey && key.length > 1 || e.shiftKey && /[A-Z0-9]/.test(key)) mods.push('Shift');
        return mods.join('+') + '+' + key;
    }

    function single(key) {
        if (!key || key.length !== 1) return null;
        return /[A-Za-z]/.test(key) ? key.toLowerCase() : key;
    }

    function onKeydown(e) {
        if (!globalRef && !caseRef) return;

        if (buffering && !(e.target && e.target.classList && e.target.classList.contains('cmdk-input'))) {
            if (e.key === 'Escape') { stopBuffering(); }
            else if (e.key === 'Backspace') { e.preventDefault(); buffer = buffer.slice(0, -1); return; }
            else if (e.key && e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) { e.preventDefault(); buffer += e.key; return; }
        }

        // Fixed keys.
        if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); clearLeader(); sendGlobal('palette'); return; }
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { if (caseRef) { e.preventDefault(); sendCase('submit'); } return; }
        if (e.key === 'Escape') { clearLeader(); sendGlobal('escape'); return; }

        // Chords (Ctrl or Alt): work while typing, like the fixed ones.
        if (e.ctrlKey || e.metaKey || e.altKey) {
            clearLeader();
            const b = bindings.get(chordName(e));
            if (b && run(b)) e.preventDefault();
            return;
        }

        // Everything else is a single key: never while typing, and not at all when switched off.
        if (singleOff || isTyping(e.target)) { clearLeader(); return; }
        const k = single(e.key);
        if (!k) return;

        if (leader) {
            clearLeader();
            const b = bindings.get('g ' + k);
            if (b && run(b)) e.preventDefault();
            return;
        }
        if (k === 'g') { leader = true; leaderTimer = setTimeout(clearLeader, 1200); return; }
        const b = bindings.get(k);
        if (b && run(b)) e.preventDefault();
    }

    function attach() {
        if (!attached) { document.addEventListener('keydown', onKeydown, true); attached = true; }
    }

    return {
        /** The command bar registers once per circuit. */
        register: function (ref) { globalRef = ref; attach(); },
        unregister: function () { globalRef = null; clearLeader(); },
        /** The open case registers while it's open. */
        registerCase: function (ref) { caseRef = ref; attach(); },
        unregisterCase: function () { caseRef = null; },
        /** cfg: { singleOff: bool, bindings: [{ keys: "g d", scope: "any"|"case", command: "go:d" }] } */
        configure: function (cfg) {
            singleOff = !!(cfg && cfg.singleOff);
            bindings = new Map();
            ((cfg && cfg.bindings) || []).forEach(function (b) { if (b && b.keys) bindings.set(b.keys, { scope: b.scope, command: b.command }); });
            clearLeader();
        }
    };
})();
