// PROD-56: uploads a large evidence file in parts (EvidenceUploadEndpoints), straight from the file the person picked or
// dropped, reporting progress to the Evidence tab. It's started and left running (a call into the page times out after a
// minute); it calls the component back with OnChunkedProgress, OnChunkedDone or OnChunkedFailed. A part that fails on the
// network, or that the server answers with 429 or 5xx, is sent again a few times; a refusal (4xx) stops with its reason.
// PROD-59: an upload that stops is kept on the server, and resume() carries it on from the next part it holds once the
// person picks the same file again (checked by name, size and the SHA-256 of its first megabyte). Only cancelling
// abandons it, so its parts are deleted.
window.imChunkedUpload = (function () {
    var running = {};
    var retryDelays = [1000, 2000, 4000, 8000];

    function headers(token, json) {
        var h = { 'RequestVerificationToken': token };
        if (json) h['Content-Type'] = 'application/json';
        return h;
    }

    // The server's answer, or an Error carrying its reason (and whether trying again could help).
    async function answer(response) {
        if (response.ok) return response.status === 204 ? null : response.json();
        var reason = 'The upload failed (' + response.status + ').';
        var setting = null;
        try { var body = await response.json(); if (body && body.error) reason = body.error; if (body && body.setting) setting = body.setting; } catch (e) { /* not JSON */ }
        var error = new Error(reason);
        error.setting = setting;   // the administrator's setting behind a refusal, for a link to it
        error.retry = response.status === 429 || response.status >= 500;
        throw error;
    }

    async function withRetry(signal, attempt) {
        for (var i = 0; ; i++) {
            try { return await answer(await attempt()); }
            catch (e) {
                if (signal.aborted || (e.retry === false) || i >= retryDelays.length) throw e;
                await new Promise(function (resolve) { setTimeout(resolve, retryDelays[i]); });
            }
        }
    }

    function call(dotnet, method) {
        var args = Array.prototype.slice.call(arguments, 2);
        return dotnet.invokeMethodAsync.apply(dotnet, [method].concat(args)).catch(function () { /* the tab is gone */ });
    }

    // PROD-59: the SHA-256 of the file's first megabyte (hex), so a resume can tell it's the same file; null where the
    // browser won't compute it (crypto.subtle needs HTTPS or localhost), and then the server won't resume it (BUG-716).
    async function sample(file) {
        try {
            if (!(window.crypto && window.crypto.subtle)) return null;
            var head = await file.slice(0, Math.min(file.size, 1024 * 1024)).arrayBuffer();
            var digest = new Uint8Array(await window.crypto.subtle.digest('SHA-256', head));
            return Array.prototype.map.call(digest, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
        } catch (e) {
            return null;
        }
    }

    // Sends the parts from where the server's plan says, then completes. open(signal, fileSample) begins or resumes the
    // upload on the server and answers { id, parts, partBytes, nextPart?, received? }.
    async function run(dotnet, key, file, token, open) {
        var job = { controller: new AbortController(), id: null, cancelled: false };
        running[key] = job;
        var signal = job.controller.signal;
        try {
            var plan = await open(signal, await sample(file));
            job.id = plan.id;
            if (plan.received) call(dotnet, 'OnChunkedProgress', key, plan.received, file.size);
            for (var part = plan.nextPart || 0; part < plan.parts; part++) {
                var from = part * plan.partBytes;
                var blob = file.slice(from, Math.min(file.size, from + plan.partBytes));
                var url = 'evidence/uploads/' + encodeURIComponent(job.id) + '/' + part;
                var sent = await withRetry(signal, function () {
                    return fetch(url, { method: 'PUT', credentials: 'same-origin', signal: signal, headers: headers(token, false), body: blob });
                });
                call(dotnet, 'OnChunkedProgress', key, sent.received, file.size);
            }
            var done = await withRetry(signal, function () {
                return fetch('evidence/uploads/' + encodeURIComponent(job.id) + '/complete',
                    { method: 'POST', credentials: 'same-origin', signal: signal, headers: headers(token, false) });
            });
            delete running[key];
            call(dotnet, 'OnChunkedDone', key, done.id);
        } catch (e) {
            delete running[key];
            if (job.cancelled && job.id) {
                // Best effort: the server also deletes abandoned parts after a day.
                fetch('evidence/uploads/' + encodeURIComponent(job.id), { method: 'DELETE', credentials: 'same-origin', headers: headers(token, false) })
                    .catch(function () { });
            }
            // Anything else keeps the upload on the server, to resume (the tab lists it).
            call(dotnet, 'OnChunkedFailed', key, job.cancelled ? '' : (e && e.message) || 'The upload stopped.', (e && e.setting) || null);
        }
    }

    // CAP-08: collection is { collectedAt, collectedFrom, collectedBy }, each optional; the server keeps it with the upload,
    // so a resume needn't send it again.
    function begin(caseId, file, description, token, collection) {
        var c = collection || {};
        return function (signal, fileSample) {
            return withRetry(signal, function () {
                return fetch('evidence/uploads/', {
                    method: 'POST', credentials: 'same-origin', signal: signal, headers: headers(token, true),
                    body: JSON.stringify({
                        caseId: caseId, name: file.name, contentType: file.type || '', size: file.size, description: description, sample: fileSample,
                        collectedAt: c.collectedAt || null, collectedFrom: c.collectedFrom || null, collectedBy: c.collectedBy || null
                    })
                });
            });
        };
    }

    function carryOn(uploadId, file, token) {
        return function (signal, fileSample) {
            return withRetry(signal, function () {
                return fetch('evidence/uploads/' + encodeURIComponent(uploadId) + '/resume', {
                    method: 'POST', credentials: 'same-origin', signal: signal, headers: headers(token, true),
                    body: JSON.stringify({ name: file.name, size: file.size, sample: fileSample })
                });
            });
        };
    }

    function picked(dotnet, key, inputId, index) {
        var input = document.getElementById(inputId);
        var file = input && input.files && input.files[index];
        if (!file) call(dotnet, 'OnChunkedFailed', key, "The file can't be read any more. Pick it again.", null);
        return file;
    }

    // run() reports its own failures; anything that still escapes it reaches the page rather than vanishing.
    function go(dotnet, key, file, token, open) {
        run(dotnet, key, file, token, open).catch(function (e) {
            delete running[key];
            call(dotnet, 'OnChunkedFailed', key, (e && e.message) || 'The upload failed.', (e && e.setting) || null);
        });
    }

    // Leaving the page (closing it, reloading, typing another address) mid-upload asks first; moving within CaseBook is
    // asked by the Evidence tab itself (UnsavedEdits).
    window.addEventListener('beforeunload', function (e) {
        if (Object.keys(running).length === 0) return;
        e.preventDefault();
        e.returnValue = '';
    });

    return {
        // inputId and index name the file input and which of its files to send (the picker's, or one dropped).
        start: function (dotnet, key, inputId, index, caseId, description, token, collection) {
            var file = picked(dotnet, key, inputId, index);
            if (file) go(dotnet, key, file, token, begin(caseId, file, description, token, collection));
        },
        // PROD-59: carries on an upload the server kept, with the same file picked again.
        resume: function (dotnet, key, inputId, index, uploadId, token) {
            var file = picked(dotnet, key, inputId, index);
            if (file) go(dotnet, key, file, token, carryOn(uploadId, file, token));
        },
        cancel: function (key) {
            var job = running[key];
            if (job) {
                job.cancelled = true;
                job.controller.abort();
            }
        },
        // PROD-59: leaving the page stops sending but keeps the upload on the server, to carry on later.
        stop: function (key) {
            var job = running[key];
            if (job) job.controller.abort();
        }
    };
})();
