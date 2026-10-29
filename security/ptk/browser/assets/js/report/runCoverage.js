// cert-x run-level assessment accompanies the native engine report. This is
// authored report content; target strings are rendered only as escaped text.
import { escapeMarkdownText } from './textEncoding.js';
import { pdfTheme, setBody } from './pdfTheme.js';

const text = value => String(value ?? '').replace(/[\x00-\x1f\x7f]+/g, ' ').trim();
function bounded(value) {
    const valueText = text(value);
    return valueText.length > 2000 ? valueText.slice(0, 2000) + ' [truncated; see JSON evidence]' : valueText;
}
export function runCoverageLines(run) {
    if (!run || typeof run !== 'object') return [];
    const coverage = run.coverage || {}, lines = [];
    lines.push('Run: ' + bounded(run.runId || 'unknown') + ' | State: ' + bounded(run.state || 'unknown'));
    if (coverage.dast) {
        const value = coverage.dast;
        lines.push('DAST: ' + bounded(value.phase || 'unreported') + ' | Probes dispatched: ' + (value.probeDispatches ?? 'unknown') + ' | Baselines dispatched: ' + (value.baselineDispatches ?? 'unknown'));
    }
    if (coverage.scaBodies || coverage.scaSources) lines.push('SCA: ' + (coverage.scaBodies?.analyzed || 0) + ' captured responses and ' + (coverage.scaSources?.analyzed || 0) + ' loaded script sources analyzed. These counts may overlap.');
    if (coverage.sast) lines.push('SAST: ' + (coverage.sast.preloaded?.analyzedScripts ?? 'unreported') + ' preloaded client scripts analyzed; ' + (coverage.sast.acquisition?.sourceGaps ?? 'unreported') + ' collection gaps. Server-side source is not inspected.');
    lines.push(bounded(coverage.recovery?.instruction || 'Assess only recorded checks and evidence. Missing coverage data or zero findings does not establish application safety.'));
    const gaps = Array.isArray(coverage.actionableGaps) ? coverage.actionableGaps : [];
    if (!gaps.length) lines.push('No actionable gaps were recorded. This is not proof of complete application coverage.');
    for (const gap of gaps.slice(0, 100)) {
        lines.push(bounded(gap.engine || 'Scan') + ' - ' + bounded(gap.summary || gap.code || 'Unresolved coverage gap'));
        if (gap.recovery?.instruction) lines.push('Next step: ' + bounded(gap.recovery.instruction));
        for (const example of (Array.isArray(gap.examples) ? gap.examples : []).slice(0, 3)) {
            const parts = [example.reason, example.url, example.documentId].filter(Boolean).map(bounded);
            if (parts.length) lines.push('Evidence: ' + parts.join(' | '));
        }
    }
    if (gaps.length > 100) lines.push((gaps.length - 100) + ' more gap groups remain in the JSON report.');
    const acquisition = run.config?.acquisition;
    if (acquisition) {
        const fields = [['maxResourceBytes', 'resource bytes'], ['maxTotalBytes', 'total acquired bytes'], ['maxScripts', 'loaded scripts'], ['drainTimeoutMs', 'drain milliseconds']];
        lines.push('Effective acquisition limits: ' + fields.filter(([key]) => Number.isFinite(acquisition[key])).map(([key, label]) => label + ' ' + acquisition[key]).join('; '));
    }
    return lines;
}
export function runCoverageMarkdown(run) {
    const lines = runCoverageLines(run);
    return lines.length ? ['## Coverage and remaining gaps', '', ...lines.map(line => '- ' + escapeMarkdownText(line)), ''].join('\n') : '';
}
export function drawRunCoverage(doc, layout, run, cursor) {
    const paragraphs = runCoverageLines(run); if (!paragraphs.length) return cursor;
    const space = height => { if (cursor + height > layout.contentBottom) { doc.addPage(); cursor = layout.contentTop; } };
    space(55); cursor = layout.drawSectionTitle('Coverage and remaining gaps', cursor + pdfTheme.spacing.md) + pdfTheme.spacing.xs;
    setBody(doc, pdfTheme); doc.setTextColor(0);
    for (const paragraph of paragraphs) {
        const lines = doc.splitTextToSize(paragraph, layout.pageWidth - layout.margin * 2);
        for (const line of lines) { space(14); doc.text(line, layout.margin, cursor); cursor += 12; }
        cursor += 6;
    }
    return cursor + pdfTheme.spacing.sm;
}
