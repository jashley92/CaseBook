// U-32/U-33: small UI-motion helpers (CSP-safe, self-hosted, no eval).
window.imMotion = {
    // Smooth-scroll an element into view by id (used by the timeline "jump to new" pill).
    // Falls back to an instant jump when the viewer prefers reduced motion.
    // Case workspace (design review P4): mark the sticky tab strip data-stuck once the case header has scrolled
    // under it, so CSS can show the one-line identity bar. Re-arming for another case replaces the observer.
    watchHead: function (headId, barId) {
        try {
            var head = document.getElementById(headId), bar = document.getElementById(barId);
            if (!head || !bar || !('IntersectionObserver' in window)) return;
            if (window._imHeadObs) window._imHeadObs.disconnect();
            var top = Number.parseFloat(getComputedStyle(bar).top) || 0;
            var obs = new IntersectionObserver(function (entries) {
                entries.forEach(function (e) {
                    if (e.isIntersecting) bar.removeAttribute('data-stuck'); else bar.setAttribute('data-stuck', '');
                });
            }, { rootMargin: '-' + top + 'px 0px 0px 0px', threshold: 0 });
            obs.observe(head);
            window._imHeadObs = obs;
        } catch (e) { /* no-op */ }
    },
    // Bring a form field into view and put the caret in it (e.g. the first field a submit found missing).
    focusId: function (id) {
        try {
            var el = document.getElementById(id);
            if (!el) return;
            el.focus({ preventScroll: true });
            var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'center' });
        } catch (e) { /* no-op */ }
    },
    scrollToId: function (id) {
        try {
            var el = document.getElementById(id);
            if (!el) return;
            var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'center' });
        } catch (e) { /* no-op */ }
    },
    // Scroll a horizontally overflowing tab strip so its active tab is visible (phones), without moving the page.
    revealActiveTab: function (selector) {
        try {
            var strip = document.querySelector(selector);
            var tab = strip && strip.querySelector('.nav-link.active');
            if (!tab || strip.scrollWidth <= strip.clientWidth) return;
            var t = tab.getBoundingClientRect(), st = strip.getBoundingClientRect();
            var target = strip.scrollLeft + (t.left - st.left) - (strip.clientWidth - t.width) / 2;
            strip.scrollLeft = Math.max(0, target);
        } catch (e) { /* no-op */ }
    },
    // The timeline's Add (CaseTimelineTab): whether its toolbar has scrolled up under the workspace's sticky tab strip,
    // so the composer opens docked instead of taking the reader back to the top; and, while it's away, data-tl-away on
    // <html>, so CSS shows the floating Add.
    timelineToolbarAway: function (id) {
        try {
            var el = document.getElementById(id);
            if (!el || !el.offsetParent) return false;
            var bar = document.getElementById('ws-sticky');
            var under = bar ? bar.getBoundingClientRect().bottom : 0;
            return el.getBoundingClientRect().bottom < under;
        } catch (e) { return false; }
    },
    // A scroll listener rather than an IntersectionObserver: it reads the toolbar's place on every scroll (cheap: one
    // rect), and keeps working in a page the browser has stopped painting, where an observer goes quiet.
    // It also moves an open composer between its place under the toolbar and the pop-out: out once the reader has
    // scrolled it fully out of view (the page is moved back by its height as it leaves, so nothing on screen moves),
    // and back once the toolbar is in view again. The gap between the two keeps it from flickering.
    watchTimelineToolbar: function (id) {
        try {
            window.imMotion.unwatchTimelineToolbar();
            var self = window.imMotion;
            var update = function () {
                var root = document.documentElement;
                var dz = document.getElementById('timeline-dropzone');
                var open = !!dz && !dz.classList.contains('d-none');
                var under = self._stickyBottom();
                if (!open) root.removeAttribute('data-tl-docked');
                else if (!root.hasAttribute('data-tl-docked')) {
                    var r = dz.getBoundingClientRect();
                    if (r.bottom < under) {
                        var h = r.height + (Number.parseFloat(getComputedStyle(dz).marginBottom) || 0);
                        root.setAttribute('data-tl-docked', '');
                        window.scrollBy({ top: -h, behavior: 'instant' });
                    }
                } else {
                    var bar = document.getElementById(id);
                    if (bar && bar.getBoundingClientRect().bottom > under + 8) root.removeAttribute('data-tl-docked');
                }
                root.toggleAttribute('data-tl-away', self.timelineToolbarAway(id));
            };
            window.addEventListener('scroll', update, { passive: true });
            window.addEventListener('resize', update, { passive: true });
            window._imTlWatch = update;
            update();
        } catch (e) { /* no-op */ }
    },
    _stickyBottom: function () {
        var bar = document.getElementById('ws-sticky');
        return bar ? bar.getBoundingClientRect().bottom : 0;
    },
    setTimelineDocked: function (on) {
        try { document.documentElement.toggleAttribute('data-tl-docked', !!on); } catch (e) { /* no-op */ }
    },
    isTimelineDocked: function () {
        try { return document.documentElement.hasAttribute('data-tl-docked'); } catch (e) { return false; }
    },
    unwatchTimelineToolbar: function () {
        try {
            if (window._imTlWatch) {
                window.removeEventListener('scroll', window._imTlWatch);
                window.removeEventListener('resize', window._imTlWatch);
                window._imTlWatch = null;
            }
            document.documentElement.removeAttribute('data-tl-away');
            document.documentElement.removeAttribute('data-tl-docked');
        } catch (e) { /* no-op */ }
    }
};
