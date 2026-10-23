// Unmodified PTK v10 propagation function, retained to reproduce the reentrancy defect.
function propagateTaint(outputValue, op, inputs = [], meta = {}) {
    if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) return;
    const maxLineage = Number.isFinite(window.__PTK_IAST_PROPAGATION_MAX_LINEAGE__)
        ? window.__PTK_IAST_PROPAGATION_MAX_LINEAGE__
        : getIastPropagationSettings().maxLineage;
    const maxStringLength = Number.isFinite(window.__PTK_IAST_PROPAGATION_MAX_STRING_LENGTH__)
        ? window.__PTK_IAST_PROPAGATION_MAX_STRING_LENGTH__
        : getIastPropagationSettings().maxStringLength;
    if (typeof outputValue === 'string' && outputValue.length > maxStringLength) return;
    const inputTaints = inputs.map(getTaintEntry).filter(Boolean).map(entry => entry.taint);
    if (!inputTaints.length) return;
    const primary = inputTaints[0];
    const primaryLineage = Array.isArray(primary?.lineage) ? primary.lineage : [];
    if (Number.isFinite(maxLineage) && maxLineage > 0 && primaryLineage.length >= maxLineage) return;
    const taint = {
        taintId: `t_${IAST_TAINT_STORE.nextTaintId++}`,
        sourceId: primary.sourceId,
        sourceKind: primary.sourceKind,
        taintKind: primary.taintKind,
        label: primary.label,
        createdAt: Date.now(),
        origin: primary.origin,
        meta: Object.assign({}, primary.meta, meta, {
            propagationMode: window.__PTK_IAST_PROPAGATION_MODE__ || getIastPropagationSettings().mode
        }),
        lineage: primaryLineage.concat([{ op, at: Date.now(), meta }]).slice(-Math.max(maxLineage, 1))
    };
    if (typeof outputValue === 'object' && outputValue !== null && IAST_TAINT_STORE.objectMap) {
        IAST_TAINT_STORE.objectMap.set(outputValue, { taint, time: Date.now() });
    } else {
        const fp = fingerprintValue(outputValue);
        IAST_TAINT_STORE.stringMap.set(fp, { taint, time: Date.now() });
        pruneTaintStore();
    }
}
