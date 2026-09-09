// White-label brand palette (X-08). Applies a freshly-derived brand token override live, without a full
// page reload, so an admin sees a colour change take effect immediately after saving. The authoritative
// copy is still emitted server-side into <style id="im-brand"> on every page load (see App.razor); this
// just keeps the current circuit in sync. CSP-safe: no inline handlers, text content only.
window.imBrand = {
    apply: function (css) {
        var el = document.getElementById('im-brand');
        if (!el) {
            el = document.createElement('style');
            el.id = 'im-brand';
            document.head.appendChild(el);
        }
        el.textContent = css || '';
    }
};
