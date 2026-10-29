// Idle-session watchdog (F-15). Detects keyboard/mouse inactivity entirely on the client, then calls
// back into the Blazor circuit at two moments only — the warning boundary and the hard deadline — so
// there is no continuous network chatter. CSP-safe: self-hosted, no inline script, no eval.
//
// Contract (called from IdleGuard.razor):
//   imIdle.start(dotNetRef, idleMs, warnMs)  -> begin watching; fires OnIdleWarning() at (idle-warn),
//                                               then OnIdleTimeout() at idle.
//   imIdle.reset()                            -> user chose "stay signed in"; resume watching from now.
//   imIdle.stop()                             -> detach everything (component disposed / session ending).
//   imIdle.rememberPage() / takeReturnPage()  -> keep the page a tab locked on, and hand it to the lock page's Resume.
//
// Once the warning is showing we intentionally stop treating activity as "still here": only an explicit
// reset() (the Stay-signed-in button) clears it, so drifting the mouse toward the button can't silently
// cancel the countdown.
window.imIdle = (function () {
    var ref = null;
    var idleMs = 0;
    var warnMs = 0;
    var last = 0;
    var warned = false;
    var timer = null;

    // Coalesced, passive listeners — cheap even on mousemove.
    var events = ['pointerdown', 'keydown', 'mousemove', 'wheel', 'scroll', 'touchstart', 'visibilitychange'];

    function onActivity(e) {
        if (warned) return;            // during the warning, ignore activity — require an explicit choice
        // BUG-550: after a sleep the first event (the wake's visibilitychange, a key) can come before the overdue tick.
        // A boundary that has already passed is acted on, not reset: the warning, or the lock past the deadline.
        if (Date.now() - last >= idleMs - warnMs) { tick(); return; }
        // BUG-714: the tab being hidden or shown isn't the person doing anything. Hiding it just before the warning reset
        // the clock, so a session left in a background tab stayed open for nearly twice the timeout. It's here only so a
        // wake is noticed promptly (above).
        if (e && e.type === 'visibilitychange') return;
        last = Date.now();
    }

    function tick() {
        var idleFor = Date.now() - last;
        if (!warned && idleFor >= idleMs - warnMs) {
            warned = true;
            if (ref) { try { ref.invokeMethodAsync('OnIdleWarning'); } catch (e) { /* circuit gone */ } }
        }
        if (idleFor >= idleMs) {
            stopTimer();
            if (ref) {
                try {
                    var call = ref.invokeMethodAsync('OnIdleTimeout');
                    if (call && call.catch) call.catch(lockFromClient);   // the circuit is gone: lock from here
                } catch (e) { lockFromClient(); }
            }
            // REV-63: the server-side lock needs a live circuit. With it down (an app-pool restart, a dropped network) the
            // call never lands, and the case stayed readable behind the reconnect overlay. If the page is still here a
            // few seconds later, the browser locks it itself.
            setTimeout(lockFromClient, 5000);
        }
    }

    // Leave for the session-expired page, past the unsaved-changes prompt (a deliberate security teardown, FR-05).
    function lockFromClient() {
        try { if (window.markdownEditor) window.markdownEditor.suppressUnloadGuard(); } catch (e) { /* best effort */ }
        rememberPage();
        window.location.replace(new URL('session-expired', document.baseURI).href);
    }

    // Resume goes back to the page the tab locked on. It's kept in this tab's sessionStorage, not the lock page's URL, so
    // the address bar of an unattended screen doesn't name the case; the lock page checks it's a page of this app
    // (LockReturnPage) and takes it once.
    var returnKey = 'im.lockReturn';

    function rememberPage() {
        try { sessionStorage.setItem(returnKey, window.location.href); } catch (e) { /* storage blocked: resume at home */ }
    }

    function takeReturnPage() {
        try {
            var page = sessionStorage.getItem(returnKey);
            sessionStorage.removeItem(returnKey);
            return page;
        } catch (e) { return null; }
    }

    function addListeners() {
        for (var i = 0; i < events.length; i++) {
            window.addEventListener(events[i], onActivity, { passive: true, capture: true });
        }
    }

    function removeListeners() {
        for (var i = 0; i < events.length; i++) {
            window.removeEventListener(events[i], onActivity, { capture: true });
        }
    }

    function stopTimer() {
        if (timer !== null) { clearInterval(timer); timer = null; }
    }

    function start(dotNetRef, idle, warn) {
        stop();                        // idempotent: replace any prior watch
        ref = dotNetRef;
        idleMs = idle;
        warnMs = warn;
        last = Date.now();
        warned = false;
        addListeners();
        timer = setInterval(tick, 1000);
    }

    function reset() {
        last = Date.now();
        warned = false;
    }

    function stop() {
        stopTimer();
        removeListeners();
        ref = null;
        warned = false;
    }

    return { start: start, reset: reset, stop: stop, rememberPage: rememberPage, takeReturnPage: takeReturnPage };
})();
