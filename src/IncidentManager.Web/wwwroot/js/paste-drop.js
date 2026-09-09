// Paste-a-screenshot & drag-drop helper (U-39 Evidence tab, U-40 Timeline tab). CSP-safe: one set of
// delegated document listeners attached from this external file (no inline handlers, no eval). It moves no
// bytes itself — it hands the clipboard image / dropped files to hidden Blazor <InputFile> elements by
// setting their FileList and firing a native 'change', so the files stream to .NET over the existing
// InputFile path (hashing, chain-of-custody, the size cap — all unchanged). Registration is idempotent and
// supports several zones (only one is ever visible at a time — they live on different workspace tabs).
window.imPasteDrop = (function () {
    let attached = false;
    const zones = []; // { zoneId, pasteInputId, dropInputId|null }

    // A zone participates only while its wrapper element is in the DOM and visible — this scopes paste to
    // the active tab and lets the listeners stay registered harmlessly across tab switches.
    function visibleZone() {
        for (const z of zones) {
            const el = document.getElementById(z.zoneId);
            if (el && el.offsetParent !== null) return { z, el };
        }
        return null;
    }

    function zoneForTarget(target) {
        for (const z of zones) {
            if (z.dropInputId && target.closest && target.closest('#' + z.zoneId)) {
                const el = document.getElementById(z.zoneId);
                if (el) return { z, el };
            }
        }
        return null;
    }

    function push(inputId, files) {
        const inp = inputId && document.getElementById(inputId);
        if (!inp || !files || !files.length) return;
        const dt = new DataTransfer();
        for (const f of files) dt.items.add(f);
        inp.files = dt.files;
        inp.dispatchEvent(new Event('change', { bubbles: true }));
    }

    function stamp() {
        const d = new Date(), p = n => String(n).padStart(2, '0');
        return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
    }

    function imagesFrom(items) {
        const imgs = [];
        for (const it of items || []) {
            if (it.kind === 'file' && it.type && it.type.indexOf('image/') === 0) {
                const f = it.getAsFile();
                if (f) {
                    const ext = (f.type.split('/')[1] || 'png').replace('jpeg', 'jpg').replace('svg+xml', 'svg');
                    imgs.push(new File([f], `pasted-screenshot-${stamp()}.${ext}`, { type: f.type }));
                }
            }
        }
        return imgs;
    }

    function onPaste(e) {
        const v = visibleZone();
        if (!v) return;
        const imgs = imagesFrom(e.clipboardData && e.clipboardData.items);
        if (imgs.length) { e.preventDefault(); push(v.z.pasteInputId, imgs); }
    }

    function onDragOver(e) {
        const v = zoneForTarget(e.target);
        if (!v) return;
        e.preventDefault();
        if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
        v.el.classList.add('im-dropping');
    }

    function onDragLeave(e) {
        for (const z of zones) {
            const el = document.getElementById(z.zoneId);
            if (el && !el.contains(e.relatedTarget)) el.classList.remove('im-dropping');
        }
    }

    function onDrop(e) {
        const v = zoneForTarget(e.target);
        if (!v) return;
        e.preventDefault();
        v.el.classList.remove('im-dropping');
        const files = e.dataTransfer && e.dataTransfer.files;
        if (files && files.length) push(v.z.dropInputId, files);
    }

    return {
        // pasteInputId: hidden InputFile that receives a pasted image. dropInputId: hidden InputFile that
        // receives dropped files (pass null to disable drop for this zone — e.g. the Timeline, paste-only).
        register: function (zoneId, pasteInputId, dropInputId) {
            if (!zones.some(z => z.zoneId === zoneId)) {
                zones.push({ zoneId, pasteInputId, dropInputId: dropInputId || null });
            }
            if (!attached) {
                document.addEventListener('paste', onPaste, true);
                document.addEventListener('dragover', onDragOver, true);
                document.addEventListener('dragleave', onDragLeave, true);
                document.addEventListener('drop', onDrop, true);
                attached = true;
            }
        }
    };
})();
