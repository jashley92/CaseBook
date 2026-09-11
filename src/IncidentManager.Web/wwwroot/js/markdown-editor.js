// Minimal interop around the vendored EasyMDE Markdown editor (CSP-safe: self-hosted, no eval, no CDN).
// Blazor owns the value: init enhances a <textarea>, getValue pulls the current Markdown on demand,
// destroy tears the instance back down to the textarea. Toolbar icons use the vendored Bootstrap Icons
// (FontAwesome auto-download is disabled so nothing is fetched from a CDN).
(function () {
    const instances = {};

    function toolbar() {
        // Each button binds an EasyMDE static action and a `bi bi-*` glyph (Bootstrap Icons, already vendored).
        return [
            { name: 'bold', action: EasyMDE.toggleBold, className: 'bi bi-type-bold', title: 'Bold' },
            { name: 'italic', action: EasyMDE.toggleItalic, className: 'bi bi-type-italic', title: 'Italic' },
            { name: 'heading', action: EasyMDE.toggleHeadingSmaller, className: 'bi bi-type-h1', title: 'Heading' },
            '|',
            { name: 'ul', action: EasyMDE.toggleUnorderedList, className: 'bi bi-list-ul', title: 'Bulleted list' },
            { name: 'ol', action: EasyMDE.toggleOrderedList, className: 'bi bi-list-ol', title: 'Numbered list' },
            { name: 'quote', action: EasyMDE.toggleBlockquote, className: 'bi bi-quote', title: 'Quote' },
            { name: 'code', action: EasyMDE.toggleCodeBlock, className: 'bi bi-code-slash', title: 'Code' },
            '|',
            { name: 'link', action: EasyMDE.drawLink, className: 'bi bi-link-45deg', title: 'Insert link' },
            { name: 'preview', action: EasyMDE.togglePreview, className: 'bi bi-eye', title: 'Toggle preview', noDisable: true }
        ];
    }

    window.markdownEditor = {
        init: function (id, initial) {
            const el = document.getElementById(id);
            if (!el || typeof EasyMDE === 'undefined') return;
            if (instances[id]) { instances[id].value(initial || ''); return; }
            instances[id] = new EasyMDE({
                element: el,
                initialValue: initial || '',
                autoDownloadFontAwesome: false, // never fetch icons from a CDN (CSP)
                spellChecker: false,            // avoids the Typo.js dictionary fetch
                status: false,
                minHeight: '150px',
                autoRefresh: { delay: 100 },    // render correctly even if created while hidden
                toolbar: toolbar(),
                shortcuts: { toggleSideBySide: null, toggleFullScreen: null }
            });
        },
        getValue: function (id) {
            return instances[id] ? instances[id].value() : '';
        },
        setValue: function (id, val) {
            if (instances[id]) instances[id].value(val || '');
        },
        focus: function (id) {                     // U-14: place the caret in the editor (keyboard shortcut)
            const mde = instances[id];
            if (mde && mde.codemirror) { try { mde.codemirror.focus(); } catch (e) { /* not ready */ } }
        },
        destroy: function (id) {
            const mde = instances[id];
            if (!mde) return;
            try { mde.toTextArea(); mde.cleanup && mde.cleanup(); } catch (e) { /* best effort */ }
            delete instances[id];
        }
    };
})();
