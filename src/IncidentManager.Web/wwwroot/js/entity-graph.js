// Interactive entity-relationship graph, powered by the locally-vendored vis-network
// (the same engine DFIR-IRIS uses). Nodes are draggable; the view zooms/pans; physics
// settle the layout. Saved node positions are restored on load, and drag-end pushes the
// arranged layout back to .NET for persistence. Called from CaseWorkspace.razor.
window.entityGraph = (function () {
    const instances = new Map(); // containerId -> { el, network, nodes, edges, dotNetRef, canPersist }

    function baseOptions() {
        // Match the active Bootstrap theme so labels stay legible on the dark canvas.
        const dark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
        const nodeFont = dark ? '#e9ecef' : '#212529';
        const labelHalo = dark ? '#212529' : '#ffffff';
        const edgeFont = dark ? '#adb5bd' : '#495057';
        const edgeColor = dark ? '#6c757d' : '#adb5bd';
        return {
            nodes: {
                shape: 'dot',
                size: 18,
                borderWidth: 2,
                shadow: { enabled: true, size: 6, x: 0, y: 1, color: 'rgba(0,0,0,0.15)' },
                font: { size: 13, face: 'system-ui, sans-serif', color: nodeFont, strokeWidth: 3, strokeColor: labelHalo }
            },
            edges: {
                arrows: { to: { enabled: true, scaleFactor: 0.7 } },
                color: { color: edgeColor, highlight: '#0d6efd', hover: '#6c757d' },
                font: { size: 11, align: 'middle', color: edgeFont, strokeWidth: 4, strokeColor: labelHalo },
                smooth: { enabled: true, type: 'dynamic' },
                width: 1.5
            },
            physics: {
                enabled: true,
                barnesHut: {
                    gravitationalConstant: -9000, centralGravity: 0.3,
                    springLength: 150, springConstant: 0.04, damping: 0.4, avoidOverlap: 0.6
                },
                stabilization: { enabled: true, iterations: 250, fit: true }
            },
            interaction: {
                hover: true, dragNodes: true, dragView: true, zoomView: true,
                multiselect: true, navigationButtons: false, tooltipDelay: 120
            },
            layout: { improvedLayout: true }
        };
    }

    function hasCoords(n) { return typeof n.x === 'number' && typeof n.y === 'number'; }

    // Strip null/undefined coordinates so vis doesn't place a node at NaN; pin saved nodes
    // during stabilization so only the un-placed newcomers flow.
    function prepareForBuild(n) {
        const m = Object.assign({}, n);
        if (hasCoords(m)) { m.fixed = { x: true, y: true }; }
        else { delete m.x; delete m.y; }
        return m;
    }

    function pushPositions(inst) {
        if (!inst.canPersist || !inst.dotNetRef) return;
        const pos = inst.network.getPositions();
        const payload = Object.keys(pos).map(function (id) { return { entityId: id, x: pos[id].x, y: pos[id].y }; });
        inst.dotNetRef.invokeMethodAsync('OnNodesMoved', payload).catch(function () { /* ignore */ });
    }

    // Map a .NET edge DTO to a vis edge, applying per-edge colour/dashes only when set
    // (attack-step edges carry a tactic colour + dashes; entity relationships use the theme default).
    function prepareEdge(e) {
        const edge = { id: e.id, from: e.from, to: e.to, label: e.label };
        if (e.dashes) edge.dashes = true;
        if (e.color) edge.color = { color: e.color, highlight: e.color, hover: e.color };
        return edge;
    }

    function build(el, containerId, nodesArr, edgesArr, dotNetRef, canPersist) {
        const nodes = new vis.DataSet(nodesArr.map(prepareForBuild));
        const edges = new vis.DataSet(edgesArr.map(prepareEdge));
        const network = new vis.Network(el, { nodes: nodes, edges: edges }, baseOptions());
        const inst = { el: el, network: network, nodes: nodes, edges: edges, dotNetRef: dotNetRef, canPersist: canPersist };
        instances.set(containerId, inst);

        network.once('stabilizationIterationsDone', function () {
            // Release the temporary pins (so saved nodes stay draggable) and freeze the layout.
            nodes.update(nodes.getIds().map(function (id) { return { id: id, fixed: false }; }));
            network.setOptions({ physics: { enabled: false } });
            network.fit({ animation: false });
        });

        network.on('dragEnd', function (params) {
            if (params && params.nodes && params.nodes.length > 0) pushPositions(inst);
        });
    }

    function syncNodes(ds, arr) {
        const incoming = new Set(arr.map(function (x) { return x.id; }));
        ds.getIds().forEach(function (id) { if (!incoming.has(id)) ds.remove(id); });
        const existing = new Set(ds.getIds());
        arr.forEach(function (n) {
            if (existing.has(n.id)) {
                // Update visuals only; keep the node's current (possibly dragged) position.
                ds.update({ id: n.id, label: n.label, title: n.title, shape: n.shape, color: n.color });
            } else {
                const m = Object.assign({}, n);
                if (!hasCoords(m)) { delete m.x; delete m.y; }
                ds.add(m);
            }
        });
    }

    function syncEdges(ds, arr) {
        const incoming = new Set(arr.map(function (x) { return x.id; }));
        ds.getIds().forEach(function (id) { if (!incoming.has(id)) ds.remove(id); });
        ds.update(arr.map(prepareEdge));
    }

    function render(containerId, nodesArr, edgesArr, dotNetRef, canPersist) {
        const el = document.getElementById(containerId);
        if (!el || typeof vis === 'undefined') return;
        let inst = instances.get(containerId);
        // If the tab was left and re-entered, the DOM node is new -> rebuild against it.
        if (inst && inst.el !== el) {
            try { inst.network.destroy(); } catch (e) { /* ignore */ }
            instances.delete(containerId);
            inst = null;
        }
        if (!inst) { build(el, containerId, nodesArr, edgesArr, dotNetRef, canPersist); return; }

        inst.dotNetRef = dotNetRef;
        inst.canPersist = canPersist;
        const existingIds = new Set(inst.nodes.getIds());
        const hasNew = nodesArr.some(function (n) { return !existingIds.has(n.id); });
        syncNodes(inst.nodes, nodesArr);
        syncEdges(inst.edges, edgesArr);

        if (hasNew) {
            // Let physics settle the newcomers around the existing (kept) nodes, then re-freeze.
            inst.network.setOptions({ physics: { enabled: true } });
            inst.network.stabilize(150);
            inst.network.once('stabilizationIterationsDone', function () {
                inst.network.setOptions({ physics: { enabled: false } });
            });
        }
    }

    function fit(containerId) {
        const i = instances.get(containerId);
        if (i) i.network.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
    }

    function setPhysics(containerId, on) {
        const i = instances.get(containerId);
        if (i) i.network.setOptions({ physics: { enabled: !!on } });
    }

    // Release manual positions and re-run the force layout from scratch, then persist the result.
    function relayout(containerId) {
        const i = instances.get(containerId);
        if (!i) return;
        // Scatter every node to a distinct starting point and unfix it before re-running physics.
        // Setting x/y to null (or leaving all nodes stacked on one point) collapses them onto (0,0),
        // where barnesHut repulsion has zero distance/direction to separate them — the layout then
        // stays frozen at the centre. Distinct seed positions give the force layout room to expand.
        const ids = i.nodes.getIds();
        const spread = Math.max(200, ids.length * 60);
        i.nodes.update(ids.map(function (id, idx) {
            const angle = (idx / Math.max(1, ids.length)) * Math.PI * 2;
            return {
                id: id, fixed: false,
                x: Math.cos(angle) * spread * 0.5 + (Math.random() - 0.5) * 40,
                y: Math.sin(angle) * spread * 0.5 + (Math.random() - 0.5) * 40
            };
        }));
        i.network.setOptions({ physics: { enabled: true } });
        i.network.stabilize(250);
        i.network.once('stabilizationIterationsDone', function () {
            i.network.setOptions({ physics: { enabled: false } });
            i.network.fit({ animation: { duration: 400 } });
            pushPositions(i);
        });
    }

    function destroy(containerId) {
        const i = instances.get(containerId);
        if (i) { try { i.network.destroy(); } catch (e) { /* ignore */ } instances.delete(containerId); }
    }

    return { render: render, fit: fit, setPhysics: setPhysics, relayout: relayout, destroy: destroy };
})();
