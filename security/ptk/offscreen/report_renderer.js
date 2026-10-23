import {buildReportModel,buildMarkdownFromExportModel,buildPdfFromExportModel,buildExecutivePdfFromReportModel,buildExportFindingFromNormalized,buildExportFindingFromSca,buildScaEntries,buildScaEntriesFromFindings,exportModel} from '../browser/assets/js/report-core.js';
import {normalizeScanResult} from '../browser/assets/js/scanResultViewModel.js';
import {partitionReportFindings} from '../browser/assets/js/report/reportingContract.js';
export function renderSecurityReport({reports=[],format='pdf',options={},meta={}}={}) {
  if(!['pdf','markdown'].includes(format))throw Error('Unsupported document report format.');
  const source=structuredClone(exportModel);source.meta={...source.meta,...meta,reportType:'cert-x security report',generatedAt:meta.generatedAt||new Date().toISOString()};
  for(const report of reports){const data=report.data||report.scan||report,engine=String(report.engine||data.engine||'').toUpperCase();if(!['DAST','IAST','SAST','SCA'].includes(engine))throw Error('Unknown report engine.');source.meta.host ||= data.host;source.meta.startTime ||= data.startedAt;source.meta.endTime=data.finishedAt||source.meta.endTime;
    const view=normalizeScanResult(data);
    if(engine==='SCA'){const findings=data.findings||[],flat=findings.some(f=>f.engine==='SCA'||f.evidence?.sca),entries=flat?buildScaEntriesFromFindings(findings):buildScaEntries(data.items||[]);source.sections.sca.push(...entries.map(buildExportFindingFromSca));}
    else {const observations=engine==='DAST'?view.findings.filter(f=>f.evidence?.dast?.meta?.executed===false&&f.evidence?.dast?.meta?.reflected===true):[];const split=partitionReportFindings(engine,view.findings.filter(f=>!observations.includes(f)));source.sections[engine.toLowerCase()].push(...split.findings.map(f=>buildExportFindingFromNormalized(f,view)));if(engine==='DAST')source.discoveries.dast.push(...split.discoveries.concat(observations).map(f=>{const projected=buildExportFindingFromNormalized(f,view);if(observations.includes(f)){projected.title+=' (reflection only)';projected.evidence.notes='Execution was not observed. '+projected.evidence.notes;}return projected;}));}
  }
  source.findings=Object.values(source.sections).flat();
  const model=buildReportModel(source,options);
  model.certXRun=meta.run;
  if(format==='markdown')return {format,mime:'text/markdown',extension:'md',text:buildMarkdownFromExportModel(model),findings:model.findings.length};
  const doc=options.preset==='technical'?buildPdfFromExportModel(model):buildExecutivePdfFromReportModel(model);
  return {format,mime:'application/pdf',extension:'pdf',bytes:Array.from(new Uint8Array(doc.output('arraybuffer'))),pages:doc.getNumberOfPages(),findings:model.findings.length};
}
