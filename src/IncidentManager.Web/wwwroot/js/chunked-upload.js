// PROD-56: uploads a large evidence file in parts (EvidenceUploadEndpoints), straight from the file the person picked or
// dropped, reporting progress to the Evidence tab. It's started and left running (a call into the page times out after a
// minute); it calls the component back with OnChunkedProgress, OnChunkedDone or OnChunkedFailed. A part that fails on the
// network, or that the server answers with 429 or 5xx, is sent again a few times; a refusal (4xx) stops with its reason.
// Cancelling, or a failure, abandons the upload on the server so its parts are deleted.
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
        try { var body = await response.json(); if (body && body.error) reason = body.error; } catch (e) { /* not JSON */ }
        var error = new Error(reason);
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

    async function send(dotnet, key, file, caseId, description, token) {
        var job = { controller: new AbortController(), id: null };
        running[key] = job;
        var signal = job.controller.signal;
        try {
            var started = await withRetry(signal, function () {
                return fetch('evidence/uploads/', {
                    method: 'POST', credentials: 'same-origin', signal: signal, headers: headers(token, true),
                    body: JSON.stringify({ caseId: caseId, name: file.name, contentType: file.type || '', size: file.size, description: description })
                });
            });
            job.id = started.id;
            for (var part = 0; part < started.parts; part++) {
                var from = part * started.partBytes;
                var blob = file.slice(from, Math.min(file.size, from + started.partBytes));
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
            if (job.id) {
                // Best effort: the server also deletes abandoned parts after a day.
                fetch('evidence/uploads/' + encodeURIComponent(job.id), { method: 'DELETE', credentials: 'same-origin', headers: headers(token, false) })
                    .catch(function () { });
            }
            call(dotnet, 'OnChunkedFailed', key, signal.aborted ? '' : (e && e.message) || 'The upload failed.');
        }
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
        start: function (dotnet, key, inputId, index, caseId, description, token) {
            var input = document.getElementById(inputId);
            var file = input && input.files && input.files[index];
            if (!file) {
                call(dotnet, 'OnChunkedFailed', key, "The file can't be read any more. Pick it again.");
                return;
            }
            // send() reports its own failures; anything that still escapes it reaches the page rather than vanishing.
            send(dotnet, key, file, caseId, description, token).catch(function (e) {
                delete running[key];
                call(dotnet, 'OnChunkedFailed', key, (e && e.message) || 'The upload failed.');
            });
        },
        cancel: function (key) {
            var job = running[key];
            if (job) job.controller.abort();
        }
    };
})();
