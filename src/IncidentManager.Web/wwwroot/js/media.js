// RD-04: tells a component whether a media query matches, now and whenever it changes, so the server can render
// layout that depends on the viewport (the case's Now/Next pane only where it fits beside the tab).
window.imMedia = (function () {
    var watches = {};
    var next = 1;
    return {
        // method: the [JSInvokable] to call with whether it matches (default OnMediaChanged). Returns a handle for
        // unwatch (0 when matchMedia isn't available).
        watch: function (dotnet, query, method) {
            if (!window.matchMedia) return 0;
            var mq = window.matchMedia(query);
            var send = function () { dotnet.invokeMethodAsync(method || 'OnMediaChanged', mq.matches).catch(function () { }); };
            if (mq.addEventListener) mq.addEventListener('change', send); else mq.addListener(send);
            var id = next++;
            watches[id] = { mq: mq, send: send };
            send();
            return id;
        },
        // BUG-37: the component calls this when it goes away, so its listeners don't outlive it.
        unwatch: function (id) {
            var w = watches[id];
            if (!w) return;
            delete watches[id];
            if (w.mq.removeEventListener) w.mq.removeEventListener('change', w.send); else w.mq.removeListener(w.send);
        }
    };
})();
