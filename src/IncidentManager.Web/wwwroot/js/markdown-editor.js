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

    // Caret-anchored autocomplete for a CodeMirror instance (EasyMDE), driven by trigger characters:
    //   @  → teammate mentions  → inserts "@Display Name " (notifies; derived on submit via getMentions)
    //   #  → case entities/IOCs → inserts "[value](entity:<id>) " (rendered as a chip by the Markdown service)
    // Type the trigger then a partial to open a dropdown; Up/Down to move, Enter/Tab/click to insert, Esc to
    // dismiss. Pure DOM, CSP-safe (no eval/fetch). `triggers` is built from init's opts.
    function buildTriggers(opts) {
        const triggers = [];
        if (opts && Array.isArray(opts.mentions) && opts.mentions.length) {
            triggers.push({
                re: /(?:^|[\s(\[])@([\p{L}\p{N}._-]{0,30})$/u,
                list: opts.mentions,                                  // {id, name}
                label: c => c.name,
                match: (c, q) => { const n = c.name.toLowerCase(); return q === '' || n.includes(q) || n.split(/\s+/).some(w => w.startsWith(q)); },
                insert: c => '@' + c.name + ' '
            });
        }
        if (opts && Array.isArray(opts.entities) && opts.entities.length) {
            triggers.push({
                re: /(?:^|[\s(\[])#([\p{L}\p{N}._\\/:-]{0,40})$/u,
                list: opts.entities,                                  // {id, value, hint}
                label: c => c.hint ? (c.value + '  ·  ' + c.hint) : c.value,
                match: (c, q) => q === '' || c.value.toLowerCase().includes(q) || (c.hint || '').toLowerCase().includes(q),
                insert: c => '[' + String(c.value).replace(/[\[\]\r\n]/g, '') + '](entity:' + c.id + ') '
            });
        }
        return triggers;
    }

    function attachAutocomplete(mde, triggers) {
        if (!triggers.length) return;
        const cm = mde.codemirror;
        const wrap = cm.getWrapperElement();
        let menu = null, items = [], active = -1, range = null, current = null;

        const close = () => { if (menu) { menu.remove(); menu = null; } items = []; active = -1; range = null; current = null; };

        function tokenBeforeCursor() {
            const cur = cm.getCursor();
            const upto = cm.getLine(cur.line).slice(0, cur.ch);
            for (const t of triggers) {
                const m = upto.match(t.re);
                if (m) return { t, partial: m[1], from: { line: cur.line, ch: cur.ch - m[1].length - 1 }, to: cur };
            }
            return null;
        }

        function highlight() { if (menu) [...menu.children].forEach((el, i) => el.classList.toggle('active', i === active)); }

        function choose(i) {
            if (range && current && items[i]) cm.replaceRange(current.insert(items[i]), range.from, range.to);
            close();
            cm.focus();
        }

        function update() {
            const tok = tokenBeforeCursor();
            if (!tok) return close();
            const q = tok.partial.toLowerCase();
            const matches = tok.t.list.filter(c => tok.t.match(c, q)).slice(0, 8);
            if (matches.length === 0) return close();

            range = { from: tok.from, to: tok.to }; items = matches; active = 0; current = tok.t;
            if (!menu) { menu = document.createElement('div'); menu.className = 'cm-mention-menu'; document.body.appendChild(menu); }
            menu.innerHTML = '';
            matches.forEach((c, i) => {
                const el = document.createElement('div');
                el.className = 'cm-mention-item' + (i === 0 ? ' active' : '');
                el.textContent = tok.t.label(c);
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
        // opts: { mentions?: [{id,name}], entities?: [{id,value,hint}] } — an array is treated as mentions
        // for backward compatibility.
        init: function (id, initial, opts) {
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
            if (Array.isArray(opts)) opts = { mentions: opts };
            if (opts && Array.isArray(opts.mentions)) mde._mentionCandidates = opts.mentions;
            try { attachAutocomplete(mde, buildTriggers(opts)); } catch (e) { /* autocomplete is an enhancement */ }
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
