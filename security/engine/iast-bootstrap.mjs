import { scopeAllows } from '../config.mjs';

// Run in each document covered by the tab's debugger registration. The same
// origin/path predicate used by dispatch admission also gates frame hooks.
export function buildIastDocumentSource(sources, scope) {
  return '(()=>{const scope=' + JSON.stringify(scope) + ';if(!(' + scopeAllows.toString() + ')(location.href,scope))return;' + sources.join('\n;\n') + '\n})();';
}
