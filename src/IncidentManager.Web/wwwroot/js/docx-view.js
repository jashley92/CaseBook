// Renders a filled Word template in the report preview, in the browser, with the vendored docx-preview library
// (CSP-safe: self-hosted, no eval, no CDN). Only the report tab needs it, so the libraries load on first use rather
// than on every page. Pictures are inlined as data: URLs (img-src allows data:, not blob:) and the document's
// embedded fonts are skipped (font-src doesn't allow data:); the fonts are then used by name where installed.
(function () {
    let loading = null;

    function load(src) {
        return new Promise((resolve, reject) => {
            const s = document.createElement('script');
            s.src = src;
            s.onload = resolve;
            s.onerror = () => reject(new Error('Could not load ' + src));
            document.head.appendChild(s);
        });
    }

    function ready() {
        loading ??= load('lib/docx-preview/jszip.min.js?v=3.10.2')
            .then(() => load('lib/docx-preview/docx-preview.min.js?v=0.4.1'))
            .catch(e => { loading = null; throw e; });
        return loading;
    }

    // BUG-549: the latest render (or clear) per container. A slower earlier one that finishes last is dropped instead of
    // replacing the preview of the template now selected.
    const latest = new WeakMap();
    const next = container => { const t = (latest.get(container) ?? 0) + 1; latest.set(container, t); return t; };

    const options = {
        className: 'docx',
        inWrapper: true,
        breakPages: true,
        renderHeaders: true,
        renderFooters: true,
        useBase64URL: true,
        ignoreFonts: true
    };

    window.imDocxView = {
        // streamRef: a DotNetStreamReference holding the .docx. Replaces whatever the container showed before.
        render: async function (container, streamRef) {
            if (!container) return;
            const token = next(container);
            const current = () => latest.get(container) === token;
            try {
                await ready();
                const data = await streamRef.arrayBuffer();   // read even when stale, so the stream is released
                if (!current()) return;
                container.replaceChildren();
                // renderAsync's own steps, split so nothing is written to the container until this render is known
                // to still be the latest.
                const doc = await window.docx.parseAsync(data, options);
                const nodes = await window.docx.renderDocument(doc, options);
                if (!current()) return;
                container.replaceChildren(...nodes);
            } catch (e) {
                if (current()) throw e;   // a superseded render's failure isn't the shown template's
            }
        },
        clear: function (container) {
            if (!container) return;
            next(container);
            container.replaceChildren();
        }
    };
})();
