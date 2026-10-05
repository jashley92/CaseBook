// RD-04: tells a component whether a media query matches, now and whenever it changes, so the server can render
// layout that depends on the viewport (the case's Now/Next pane only where it fits beside the tab).
window.imMedia = {
    watch: function (dotnet, query) {
        if (!window.matchMedia) return false;
        var mq = window.matchMedia(query);
        var send = function () { dotnet.invokeMethodAsync('OnMediaChanged', mq.matches).catch(function () { }); };
        if (mq.addEventListener) mq.addEventListener('change', send); else mq.addListener(send);
        send();
        return true;
    }
};
