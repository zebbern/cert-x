// PTK retains later occurrences in samples while keeping the first occurrence
// as its canonical evidence. Compare the selected occurrence, not stale primary data.
function projectIast(findings, marker) {
  return findings.flatMap(finding => {
    const evidence = finding.evidence?.iast || {};
    const sources = (evidence.sources || []).filter(item => String(item.raw || item.value || item.sourceValuePreview || '').includes(marker));
    const samples = (evidence.samples || []).filter(item => String(item.matched || '').includes(marker));
    if (!sources.length && !samples.length) return [];
    const kinds = sources.map(item => item.sourceKind || item.kind).concat(samples.map(item => item.sourceKind)).filter(Boolean);
    // These fixtures use document-local query/message/storage sources. Sample
    // URLs retain the document identity when primary source metadata is older.
    const locations = sources.map(item => item.location).concat(samples.map(item => item.url)).filter(Boolean);
    return [{ ruleId: finding.ruleId, moduleId: finding.moduleId, sourceKinds: [...new Set(kinds)].sort(), sink: evidence.sinkId, sourceLocations: [...new Set(locations)].sort() }];
  }).sort((a,b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}
module.exports = { projectIast };
