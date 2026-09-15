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

    // Inline @mention autocomplete for a CodeMirror instance (EasyMDE). `candidates` is [{id, name}].
    // Type "@" then a partial name to open a caret-anchored dropdown; Up/Down to move, Enter/Tab/click to
    // insert "@Display Name ". Mentions are derived from the text on demand (getMentions), so deleting the
    // inserted token removes the mention — no hidden state to drift. Pure DOM, CSP-safe (no eval/fetch).
    function attachMentions(mde, candidates) {
        const cm = mde.codemirror;
        const wrap = cm.getWrapperElement();
        let menu = null, items = [], active = -1, range = null;

        const close = () => { if (menu) { menu.remove(); menu = null; } items = []; active = -1; range = null; };

        function tokenBeforeCursor() {
            const cur = cm.getCursor();
            const upto = cm.getLine(cur.line).slice(0, cur.ch);
            // "@" must start a line or follow whitespace / an opening bracket; partial has no spaces.
            const m = upto.match(/(?:^|[\s(\[])@([\p{L}\p{N}._-]{0,30})$/u);
            if (!m) return null;
            const partial = m[1];
            return { partial, from: { line: cur.line, ch: cur.ch - partial.length - 1 }, to: cur };
        }

        function highlight() {
            if (menu) [...menu.children].forEach((el, i) => el.classList.toggle('active', i === active));
        }

        function choose(i) {
            if (range && items[i]) cm.replaceRange('@' + items[i].name + ' ', range.from, range.to);
            close();
            cm.focus();
        }

        function update() {
            const t = tokenBeforeCursor();
            if (!t) return close();
            const q = t.partial.toLowerCase();
            const matches = candidates.filter(c => {
                const n = c.name.toLowerCase();
                return q === '' || n.includes(q) || n.split(/\s+/).some(w => w.startsWith(q));
            }).slice(0, 8);
            if (matches.length === 0) return close();

            range = { from: t.from, to: t.to }; items = matches; active = 0;
            if (!menu) { menu = document.createElement('div'); menu.className = 'cm-mention-menu'; document.body.appendChild(menu); }
            menu.innerHTML = '';
            matches.forEach((c, i) => {
                const el = document.createElement('div');
                el.className = 'cm-mention-item' + (i === 0 ? ' active' : '');
                el.textContent = c.name;
                el.addEventListener('mousedown', ev => { ev.preventDefault(); choose(i); });
                menu.appendChild(el);
            });
            const coords = cm.cursorCoords(true, 'page');
            menu.style.left = coords.left + 'px';
            menu.style.top = (coords.bottom + 2) + 'px';
        }

        cm.on('inputRead', update);
        cm.on('cursorActivity', () => { if (menu) update(); });
        cm.on('blur', () => setTimeout(close, 150));
        // Capture phase so we intercept navigation keys before CodeMirror moves the caret.
        wrap.addEventListener('keydown', e => {
            if (!menu) return;
            if (e.key === 'ArrowDown') { active = (active + 1) % items.length; highlight(); }
            else if (e.key === 'ArrowUp') { active = (active - 1 + items.length) % items.length; highlight(); }
            else if (e.key === 'Enter' || e.key === 'Tab') { choose(active); }
            else if (e.key === 'Escape') { close(); }
            else return;
            e.preventDefault(); e.stopPropagation();
        }, true);
    }

    window.markdownEditor = {
        init: function (id, initial, candidates) {
            const el = document.getElementById(id);
            if (!el || typeof EasyMDE === 'undefined') return;
            if (instances[id]) { instances[id].value(initial || ''); return; }
            const mde = new EasyMDE({
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
            instances[id] = mde;
            if (Array.isArray(candidates) && candidates.length) {
                mde._mentionCandidates = candidates;
                try { attachMentions(mde, candidates); } catch (e) { /* mentions are an enhancement */ }
            }
        },
        // Ids of the mention candidates whose "@Display Name" token currently appears in the text.
        getMentions: function (id) {
            const mde = instances[id];
            if (!mde || !mde._mentionCandidates) return [];
            const text = mde.value();
            return mde._mentionCandidates.filter(c => text.includes('@' + c.name)).map(c => c.id);
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
