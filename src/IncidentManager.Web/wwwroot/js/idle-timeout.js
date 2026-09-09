// Idle-session watchdog (F-15). Detects keyboard/mouse inactivity entirely on the client, then calls
// back into the Blazor circuit at two moments only — the warning boundary and the hard deadline — so
// there is no continuous network chatter. CSP-safe: self-hosted, no inline script, no eval.
//
// Contract (called from IdleGuard.razor):
//   imIdle.start(dotNetRef, idleMs, warnMs)  -> begin watching; fires OnIdleWarning() at (idle-warn),
//                                               then OnIdleTimeout() at idle.
//   imIdle.reset()                            -> user chose "stay signed in"; resume watching from now.
//   imIdle.stop()                             -> detach everything (component disposed / session ending).
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

    function onActivity() {
        if (warned) return;            // during the warning, ignore activity — require an explicit choice
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
            if (ref) { try { ref.invokeMethodAsync('OnIdleTimeout'); } catch (e) { /* circuit gone */ } }
        }
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

    return { start: start, reset: reset, stop: stop };
})();
