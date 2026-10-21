// Minimal interop around the vendored EasyMDE Markdown editor (CSP-safe: self-hosted, no eval, no CDN).
// Blazor owns the value: init enhances a <textarea>, getValue pulls the current Markdown on demand,
// destroy tears the instance back down to the textarea. Toolbar icons use the vendored Bootstrap Icons
// (FontAwesome auto-download is disabled so nothing is fetched from a CDN).
(function () {
    const instances = {};

    function toolbar(opts) {
        // Each button binds an EasyMDE static action and a `bi bi-*` glyph (Bootstrap Icons, already vendored).
        return [
            { name: 'bold', action: EasyMDE.toggleBold, className: 'bi bi-type-bold', title: 'Bold' },
            { name: 'italic', action: EasyMDE.toggleItalic, className: 'bi bi-type-italic', title: 'Italic' },
            { name: 'heading', action: EasyMDE.toggleHeadingSmaller, className: 'bi bi-type-h1', title: 'Heading' },
            '|',
            { name: 'ul', action: EasyMDE.toggleUnorderedList, className: 'bi bi-list-ul', title: 'Bulleted list' },
            { name: 'ol', action: EasyMDE.toggleOrderedList, className: 'bi bi-list-ol', title: 'Numbered list' },
            // BUG-412: sub-bullets. Tab / Shift+Tab do the same on a list line; the buttons say so.
            { name: 'indent', className: 'bi bi-text-indent-left', title: 'Indent: make a sub-bullet (Tab)',
              action: editor => { const cm = editor.codemirror; cm.execCommand('indentMore'); cm.focus(); } },
            { name: 'outdent', className: 'bi bi-text-indent-right', title: 'Outdent (Shift+Tab)',
              action: editor => { const cm = editor.codemirror; cm.execCommand('indentLess'); cm.focus(); } },
            { name: 'quote', action: EasyMDE.toggleBlockquote, className: 'bi bi-quote', title: 'Quote' },
            { name: 'code', action: EasyMDE.toggleCodeBlock, className: 'bi bi-code-slash', title: 'Code' },
            '|',
            { name: 'link', action: EasyMDE.drawLink, className: 'bi bi-link-45deg', title: 'Insert link' },
            // INV-50: tagging without remembering the "[[" shortcut (only where the editor offers entities).
            ...(opts && !Array.isArray(opts) && Array.isArray(opts.entities) && opts.entities.length ? [{
                name: 'tag-entity', className: 'bi bi-tag', title: 'Tag an entity / IOC ([[)',
                action: editor => { const cm = editor.codemirror; cm.replaceSelection('[['); cm.focus(); if (editor._openTagMenu) editor._openTagMenu(); }
            }] : []),
            { name: 'preview', action: EasyMDE.togglePreview, className: 'bi bi-eye', title: 'Toggle preview', noDisable: true }
        ];
    }

    // Caret-anchored autocomplete for a CodeMirror instance (EasyMDE), driven by trigger characters:
    //   @  → teammate mentions  → inserts "@Display Name " (notifies; derived on submit via getMentions)
    //   [[ → case entities/IOCs → inserts "[value](entity:<id>) " (rendered as a chip by the Markdown service).
    //        INV-50: was "#", which is Markdown's heading marker and common in ordinary text ("ticket #4521").
    // Type the trigger then a partial to open a dropdown; Up/Down to move, Enter/Tab/click to insert, Esc to
    // dismiss. Pure DOM, CSP-safe (no eval/fetch). `triggers` is built from init's opts.
    function buildTriggers(opts) {
        const triggers = [];
        if (opts && Array.isArray(opts.mentions) && opts.mentions.length) {
            triggers.push({
                re: /(?:^|[\s(\[])@([\p{L}\p{N}._-]{0,30})$/u,
                lead: 1,
                list: opts.mentions,                                  // {id, name}
                label: c => c.name,
                match: (c, q) => { const n = c.name.toLowerCase(); return q === '' || n.includes(q) || n.split(/\s+/).some(w => w.startsWith(q)); },
                insert: c => '@' + c.name + ' '
            });
        }
        // FR-49: offered with no entities yet too, where a tag can add one (window.imTagAdd).
        if (opts && Array.isArray(opts.entities)) {
            triggers.push({
                // Spaces are allowed after "[[" (entity labels have them); the opener is deliberate, so it opens at once.
                // FR-49: and "@", so an account or an email address can be typed to be added.
                re: /(?:^|[\s(])\[\[([\p{L}\p{N}._\\/:@ -]{0,40})$/u,
                lead: 2,
                closer: ']]',
                list: opts.entities,                                  // {id, value, hint}
                label: c => c.hint ? (c.value + '  ·  ' + c.hint) : c.value,
                match: (c, q) => q === '' || c.value.toLowerCase().includes(q) || (c.hint || '').toLowerCase().includes(q),
                insert: c => '[' + linkLabel(c.value) + '](entity:' + c.id + ') '
            });
        }
        return triggers;
    }

    // C13 (wave 2): a tag's label escaped for the text of a [label](entity:id) link, as MarkdownText.LinkLabel does on the
    // server. A backslash escapes the character after it, so a label like C:\Temp\ escaped the closing bracket and the tag
    // showed as raw text; brackets used to be dropped, which changed the label. Backslashes and brackets are escaped, and
    // line breaks, which end a link, become spaces.
    function linkLabel(value) {
        return String(value).replace(/[\r\n]+/g, ' ').replace(/[\\\[\]]/g, '\\$&');
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
                if (m) return { t, partial: m[1], from: { line: cur.line, ch: cur.ch - m[1].length - t.lead }, to: cur };
            }
            return null;
        }

        function highlight() { if (menu) [...menu.children].forEach((el, i) => el.classList.toggle('active', i === active)); }

        function choose(i) {
            if (range && current && items[i] && items[i].add) {   // FR-49: added on the server first, then tagged
                const offer = items[i], list = current.list;
                window.imTagAdd.add(offer.type, offer.value).then(r => {
                    if (!r || !menu) return close();
                    items[i] = { id: r.id, value: r.value, hint: r.hint };
                    list.push(items[i]);
                    choose(i);
                });
                return;
            }
            if (range && current && items[i]) {
                // A closer typed (or auto-inserted) after the caret, e.g. "]]", is consumed with the tag.
                let to = range.to;
                if (current.closer && cm.getLine(to.line).slice(to.ch, to.ch + current.closer.length) === current.closer)
                    to = { line: to.line, ch: to.ch + current.closer.length };
                cm.replaceRange(current.insert(items[i]), range.from, to);
            }
            close();
            cm.focus();
        }

        function update() {
            const tok = tokenBeforeCursor();
            if (!tok) return close();
            const q = tok.partial.toLowerCase();
            let matches = tok.t.list.filter(c => tok.t.match(c, q)).slice(0, 8);
            if (tok.t.closer && window.imTagAdd)   // FR-49: a tag that names nothing on the case can add it
                matches = matches.concat(window.imTagAdd.offers(tok.partial,
                    tok.t.list.some(c => c.value.toLowerCase() === q.trim())));
            if (matches.length === 0) return close();

            range = { from: tok.from, to: tok.to }; items = matches; active = 0; current = tok.t;
            if (!menu) { menu = document.createElement('div'); menu.className = 'cm-mention-menu'; document.body.appendChild(menu); }
            menu.innerHTML = '';
            matches.forEach((c, i) => {
                const el = document.createElement('div');
                el.className = 'cm-mention-item' + (i === 0 ? ' active' : '') + (c.add ? ' cm-mention-add' : '');
                el.textContent = c.add ? c.text : tok.t.label(c);
                el.addEventListener('mousedown', ev => { ev.preventDefault(); choose(i); });
                menu.appendChild(el);
            });
            const coords = cm.cursorCoords(true, 'page');
            // FR-61: kept inside the window. Near the right edge (the timeline's pop-out sits there) the list shifts left
            // rather than running off it, and near the bottom it opens above the caret.
            const view = document.documentElement, gap = 8;
            menu.style.left = '0px'; menu.style.top = '0px';   // measured at its natural width, not squeezed at the edge
            const maxLeft = window.scrollX + view.clientWidth - menu.offsetWidth - gap;
            menu.style.left = Math.max(window.scrollX + gap, Math.min(coords.left, maxLeft)) + 'px';
            const below = coords.bottom + 2, h = menu.offsetHeight;
            const fitsBelow = below + h <= window.scrollY + view.clientHeight - gap;
            menu.style.top = (fitsBelow || coords.top - 2 - h < window.scrollY ? below : coords.top - 2 - h) + 'px';
        }

        cm.on('inputRead', update);
        mde._openTagMenu = update;   // INV-50: the toolbar's "Tag entity" button inserts "[[" and opens the list
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

    // BUG-611: an editor holds unsaved text when it differs from its seed: the saved text it was given (init, setValue),
    // or '' for text that isn't saved anywhere (a new composer, a draft put back). An edit left as it opened isn't dirty.
    function isDirty(m) {
        try { return (m.value() || '').trim() !== (m._seed || '').trim(); } catch (e) { return false; }
    }

    // The seed for a value put in the editor: `saved` when it's given (a string), else the value itself.
    function seedOf(val, saved) {
        return typeof saved === 'string' ? saved : (val || '');
    }

    window.markdownEditor = {
        // opts: { mentions?: [{id,name}], entities?: [{id,value,hint}], saved?: string } — an array is treated as mentions
        // for backward compatibility. BUG-611: `saved` is the text already saved behind `initial` ('' when none is);
        // left out, `initial` is.
        init: function (id, initial, opts) {
            const el = document.getElementById(id);
            if (!el || typeof EasyMDE === 'undefined') return;
            const saved = opts && !Array.isArray(opts) ? opts.saved : undefined;
            if (instances[id]) { instances[id].value(initial || ''); instances[id]._seed = seedOf(initial, saved); return; }
            const mde = new EasyMDE({
                element: el,
                initialValue: initial || '',
                autoDownloadFontAwesome: false, // never fetch icons from a CDN (CSP)
                spellChecker: false,            // avoids the Typo.js dictionary fetch
                status: false,
                minHeight: '150px',
                autoRefresh: { delay: 100 },    // render correctly even if created while hidden
                toolbar: toolbar(opts),
                shortcuts: { toggleSideBySide: null, toggleFullScreen: null }
            });
            mde._seed = seedOf(initial, saved);
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
        // BUG-611: `saved` as for init: '' when the text put back isn't saved anywhere (a stashed draft).
        setValue: function (id, val, saved) {
            if (!instances[id]) return;
            instances[id].value(val || '');
            instances[id]._seed = seedOf(val, saved);
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
        },
        // FR-05: does any mounted composer still hold unsubmitted text (BUG-611: other than its seed)? Drives the
        // unsaved-changes guards (browser beforeunload below + the in-app NavigationLock in the workspace).
        anyDirty: function () {
            return Object.values(instances).some(isDirty);
        },
        // BUG-578 (C7): the ids of the editors holding text, for UnsavedEdits.PendingAsync: only those inside an element
        // `within` selects (a tab's body, the Now/Next pane, a side panel) when it's given, and never those in `except`
        // (a composer whose text survives what's about to happen, as FR-02's stash survives a tab switch). BUG-611: the
        // stash keeps new text only, so an excepted editor editing saved text (it has a seed) is still reported.
        dirtyIds: function (within, except) {
            const skip = new Set(except || []);
            const roots = within ? Array.from(document.querySelectorAll(within)) : null;
            return Object.keys(instances).filter(function (id) {
                const m = instances[id];
                if ((skip.has(id) && !(m._seed || '').trim()) || !isDirty(m)) return false;
                if (!roots) return true;
                const el = document.getElementById(id);
                return !!el && roots.some(function (r) { return r.contains(el); });
            });
        },
        // FR-05: let a deliberate, security-driven teardown (the idle lock, Lock now, the client fallback) bypass
        // every beforeunload prompt, this one and any other page's (BUG-369), so an unattended screen is never trapped
        // behind a native dialog. One-shot: it clears itself once the unload it was meant for has passed.
        suppressUnloadGuard: function () {
            suppressUnload = true;
            setTimeout(function () { suppressUnload = false; }, 4000);
        }
    };

    // FR-05: warn before a full-page exit (refresh / tab close / typing a new URL / external link) when a
    // Markdown composer still holds unsubmitted text. In-app SPA navigation is guarded separately by the
    // NavigationLock in the case workspace; this covers the browser-level unload that guard can't see. It
    // only prompts when actually dirty (and never when suppressed for the idle-lock), so it's otherwise inert.
    let suppressUnload = false;
    // BUG-369: other pages register their own beforeunload, e.g. Blazor's NavigationLock ConfirmExternalNavigation on
    // Administration (blazor.web.js adds a plain window listener that always calls preventDefault). A capture-phase
    // listener on window runs before every bubble-phase one there, so while a lock is under way it stops them all.
    window.addEventListener('beforeunload', function (e) {
        if (suppressUnload) e.stopImmediatePropagation();
    }, { capture: true });
    window.addEventListener('beforeunload', function (e) {
        if (suppressUnload) return;
        let dirty = false;
        try {
            dirty = Object.values(instances).some(isDirty);   // BUG-611: as the in-app prompts judge it
        } catch (err) { return; /* never block an unload on an error */ }
        if (dirty) { e.preventDefault(); e.returnValue = ''; }
    });
})();
