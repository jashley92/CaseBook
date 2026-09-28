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

    window.imDocxView = {
        // streamRef: a DotNetStreamReference holding the .docx. Replaces whatever the container showed before.
        render: async function (container, streamRef) {
            if (!container) return;
            await ready();
            const data = await streamRef.arrayBuffer();
            container.replaceChildren();
            await window.docx.renderAsync(data, container, container, {
                className: 'docx',
                inWrapper: true,
                breakPages: true,
                renderHeaders: true,
                renderFooters: true,
                useBase64URL: true,
                ignoreFonts: true
            });
        },
        clear: function (container) {
            if (container) container.replaceChildren();
        }
    };
})();
