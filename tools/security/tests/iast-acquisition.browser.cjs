// Bounded acquisition contract in real Chromium. Markers are inert HTML.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'C:/Users/zeb/AppData/Roaming/npm/node_modules/@playwright/cli/node_modules/playwright-core');
const { resolveReference } = require('../prepare-reference.cjs');
const { projectIast } = require('./collection-projection.cjs');

const root = path.resolve(__dirname, '../../..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cert-x-iast-acquisition-'));
const evidenceDir = path.join(root, 'tools/security/evidence');
fs.mkdirSync(evidenceDir, { recursive: true });
const evidenceFile = path.join(evidenceDir, 'iast-acquisition-browser.json');
const marker = name => `<b>CERTX_IAST_${name}</b>`;
const evidence = { schema: 1, scope: 'Local inert browser acquisition; matching values are observations, not exploit proof.' };
let browser, server, foreignServer, reference;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const save = () => fs.writeFileSync(evidenceFile, JSON.stringify(evidence, null, 2));
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

function application() {
    return `<!doctype html><title>IAST acquisition fixture</title>
<div id="sink"></div><div id="safe"></div><script>
window.documentIdentity=crypto.randomUUID();
window.nativeMessageDataGetter=Object.getOwnPropertyDescriptor(MessageEvent.prototype,'data').get;
window.calls={object:0,safe:0,large:0,foreign:0,accessor:0};window.identities=[];window.accessorReads=0;window.accessorStacks=[];
window.addEventListener('message',event=>{
  if(event.source!==window&&event.source!==document.querySelector('iframe')?.contentWindow)return;
  const data=event.data;
  if(data?.tag==='accessor'){calls.accessor++;return;}
  if(data?.tag==='object'||data?.tag==='safe'||data?.tag==='large'||data?.tag==='foreign'){
    calls[data.tag]++;
    identities.push({tag:data.tag,same:data===nativeMessageDataGetter.call(event),repeat:data===event.data,cycle:data.self===data,origin:event.origin});
    const value=data.payload.items[0].html;
    if(data.tag==='safe')document.querySelector('#safe').textContent=value;
    else document.querySelector('#sink').innerHTML=value;
  }
});
window.sendObject=(tag,value)=>{
  const payload={tag,payload:{items:[{html:value}]}};
  payload.self=payload;window.postMessage(payload,location.origin);
};
window.sendLarge=value=>{
  const items=Array.from({length:33},(_,index)=>({html:index===0?value:'padding'}));
  window.postMessage({tag:'large',payload:{items}},location.origin);
};
window.sendAccessor=()=>{
  const data={tag:'accessor'};
  Object.defineProperty(data,'html',{enumerable:true,get(){accessorReads++;accessorStacks.push(new Error().stack);return '${marker('ACCESSOR')}';}});
  window.dispatchEvent(new MessageEvent('message',{data,origin:location.origin,source:window}));
};
window.renderQuery=(value)=>{
  history.pushState({route:'inert'},'',location.pathname+'?collector='+encodeURIComponent(value));
  document.querySelector('#sink').innerHTML=new URLSearchParams(location.search).get('collector');
};
window.renderState=(value,safe=false)=>{
  history.replaceState({payload:{items:[{html:value}]}},'','/state');
  (safe?document.querySelector('#safe'):document.querySelector('#sink'))[safe?'textContent':'innerHTML']=history.state.payload.items[0].html;
};
</script>`;
}

async function run(extension, integrated, origin, foreignOrigin) {
    const side = integrated ? 'owned' : 'reference';
    console.log('IAST-ACQUISITION', side);
    browser = await chromium.launchPersistentContext(path.join(temp, side), {
        headless: true,
        executablePath: require('../../chromium-path.cjs'),
        args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension]
    });
    const worker = browser.serviceWorkers()[0] || await browser.waitForEvent('serviceworker');
    await worker.evaluate(async owned => {
        if (owned) await certXSecurity.ready;
        else {
            for (let i = 0; i < 200 && !globalThis.ptk_app; i++) await new Promise(r => setTimeout(r, 25));
            await ptk_app.ready; ptk_app.devLocalConfig.automationEnabled = true;
        }
    }, integrated);
    const page = await browser.newPage();
    await page.goto(origin + '/app');
    const initialIdentity = await page.evaluate(() => documentIdentity);
    const tabId = await worker.evaluate(async url => (await chrome.tabs.query({})).find(tab => tab.url === url).id, page.url());
    const context = { owner: 'iast-acquisition', tabId, scope: { origins: [origin, foreignOrigin], excludePaths: [] }, config: { preset: 'ptk-defaults', scanStrategy: 'SMART', runCve: false } };
    const started = await worker.evaluate(async ({ owned, context }) => {
        if (owned) return certXSecurity.runtime.invoke('startScan', { tabId: context.tabId, engines: ['IAST'], options: context.config }, context);
        const tab = await chrome.tabs.get(context.tabId);
        return ptk_app.automation.msg_session_start({ pageUrl: tab.url, options: { engines: ['IAST'], policyCode: 'SMART', runCve: false } }, { id: chrome.runtime.id, url: tab.url, frameId: 0, tab });
    }, { owned: integrated, context });
    assert.ok(started.sessionId, JSON.stringify(started));
    await page.waitForFunction(() => globalThis.__PTK_IAST_AGENT_LOADED__ === true && globalThis.__PTK_IAST_AGENT_AUTHORIZED__ === true && globalThis.__PTK_IAST_DEBUG_STATE__?.().activeRuleIds?.length > 0);
    const snapshot = async () => JSON.parse(JSON.stringify(await worker.evaluate(() => ptk_app.iast.scanResult)));
    const steps = {};
    const take = async (name, value) => {
        await sleep(800);
        const scan = await snapshot();
        steps[name] = { observations: projectIast(scan.findings || [], value), findings: (scan.findings || []).filter(f => (f.evidence?.iast?.sources || []).some(s => String(s.raw || '').includes(value))) };
        return steps[name];
    };
    await page.evaluate(value => sendObject('object', value), marker('OBJECT'));
    await page.waitForFunction(() => calls.object === 1);
    await take('object', marker('OBJECT'));
    await page.evaluate(value => sendObject('safe', value), marker('SAFE'));
    await page.waitForFunction(() => calls.safe === 1);
    await take('safe', marker('SAFE'));
    await page.evaluate(value => { history.pushState({}, '', '/large'); sendLarge(value); }, marker('LARGE'));
    await page.waitForFunction(() => calls.large === 1);
    await take('large', marker('LARGE'));
    await page.evaluate(() => sendAccessor());
    await page.waitForFunction(() => calls.accessor === 1);
    steps.accessorReads = await page.evaluate(() => accessorReads);
    steps.accessorStacks = await page.evaluate(() => accessorStacks.slice());
    await page.evaluate(value => renderQuery(value), marker('QUERY'));
    await take('query', marker('QUERY'));
    await page.evaluate(value => renderState(value), marker('STATE'));
    await take('state', marker('STATE'));
    await page.evaluate(value => renderState(value, true), marker('STATE_SAFE'));
    await take('stateSafe', marker('STATE_SAFE'));
    await page.evaluate(url => {
        history.pushState({route:'foreign'},'','/foreign');
        const frame = document.createElement('iframe');
        frame.src = url + '/frame'; document.body.append(frame);
    }, foreignOrigin);
    await page.waitForFunction(() => calls.foreign === 1);
    await take('foreign', marker('FOREIGN'));
    const contract = await page.evaluate(() => {
        const getter = Object.getOwnPropertyDescriptor(MessageEvent.prototype, 'data').get;
        const error = (fn, receiver) => { try { fn.call(receiver); return null; } catch (e) { return e.name; } };
        const receivers = [{}, new Event('message'), Object.create(MessageEvent.prototype)];
        return { documentIdentity, calls, identities, accessorReads, receiverErrors: receivers.map(value => [error(nativeMessageDataGetter, value), error(getter, value)]), staleQuery: Object.keys(window.__IAST_TAINTED__ || {}).filter(key => key.startsWith('query:')), stateKeys: Object.keys(window.__IAST_TAINTED__ || {}).filter(key => key.startsWith('history:state:')) };
    });
    await worker.evaluate(async ({ owned, sessionId, context }) => {
        if (owned) return certXSecurity.runtime.invoke('stopScan', { sessionId }, context);
        const tab = await chrome.tabs.get(context.tabId);
        return ptk_app.automation.msg_session_end({ options: { sessionId, sessionScope: 'current-tab' }, wait: true }, { id: chrome.runtime.id, url: tab.url, frameId: 0, tab });
    }, { owned: integrated, sessionId: started.sessionId, context });
    const stopped = await snapshot();
    await page.evaluate(value => sendObject('object', value), marker('AFTER_STOP'));
    await page.waitForFunction(() => calls.object === 2);
    await page.evaluate(value => {
        history.pushState({ payload: { html: value } }, '', '/stopped?collector=' + encodeURIComponent(value));
        document.querySelector('#sink').innerHTML = history.state.payload.html;
    }, marker('STOP_STATE'));
    await sleep(800);
    const postStop = await snapshot();
    const stoppedSources = await page.evaluate(() => Object.values(window.__IAST_TAINTED__ || {}).filter(value => String(value).includes('CERTX_IAST_STOP_STATE')));
    const result = { steps, contract, initialIdentity, stopUnchanged: JSON.stringify(stopped.findings) === JSON.stringify(postStop.findings), stoppedSources, finalFindingCount: stopped.findings.length };
    evidence[side] = result; save();
    assert.equal(contract.documentIdentity, initialIdentity);
    assert.ok(contract.identities.every(item => item.same && item.repeat));
    assert.equal(contract.identities.find(item => item.tag === 'object')?.cycle, true, 'Structured-clone cycle must remain intact');
    assert.ok(contract.receiverErrors.every(([native, current]) => native === 'TypeError' && current === native));
    assert.ok(result.stopUnchanged);
    if (integrated) assert.deepEqual(stoppedSources, [], 'Stopped history mutation must not acquire a new source');
    assert.equal(steps.safe.observations.length, 0);
    assert.equal(steps.large.observations.length, 0, 'Oversized array is intentionally outside the acquisition bound');
    assert.equal(steps.stateSafe.observations.length, 0);
    if (integrated) {
        assert.equal(steps.accessorReads, 1, 'Native MessageEvent construction reads the accessor once');
        assert.ok(steps.accessorStacks.every(stack => !stack.includes('safeSerializeValue') && !stack.includes('recordWindowMessage')), 'Agent must not invoke message object accessor');
        assert.deepEqual(contract.staleQuery, [], 'History replacement must purge stale URL query source');
        assert.ok(steps.state.findings.some(f => (f.evidence?.iast?.sources || []).some(s => String(s.key || s.source).includes('history:state:payload.items.0.html'))));
        for (const [name, kind] of [['object', 'postMessage'], ['query', 'query'], ['state', 'historyState'], ['foreign', 'postMessage']])
            assert.ok(steps[name].observations.some(item => item.sink === 'dom.innerHTML' && item.sourceKinds.includes(kind)), `Missing ${name} source/sink observation`);
        assert.ok(steps.foreign.findings.some(f => f.evidence?.iast?.primaryClass === 'observation'
            && f.evidence?.iast?.detection?.details?.messageOrigin === foreignOrigin
            && (f.evidence?.iast?.sources || []).some(s => s.origin === foreignOrigin && s.isCrossOriginMessage === true)
            && f.location?.url === origin + '/foreign'), 'Foreign frame origin and receiving document must be recorded as observation');
    } else {
        for (const name of ['object', 'query', 'state', 'foreign']) assert.equal(steps[name].observations.length, 0, `Original baseline ${name}`);
    }
    await browser.close(); browser = null;
    return result;
}

async function main() {
    reference = resolveReference(process.env.PTK_REFERENCE_ROOT);
    evidence.referenceSha256 = reference.sha256;
    server = http.createServer((_req, res) => { res.setHeader('Content-Type', 'text/html'); res.end(application()); });
    await listen(server);
    const origin = 'http://127.0.0.1:' + server.address().port;
    foreignServer = http.createServer((_req, res) => { res.setHeader('Content-Type', 'text/html'); res.end(`<script>parent.postMessage({tag:'foreign',payload:{items:[{html:${JSON.stringify(marker('FOREIGN'))}}]}},${JSON.stringify(origin)})</script>`); });
    await listen(foreignServer);
    const foreignOrigin = 'http://127.0.0.1:' + foreignServer.address().port;
    evidence.origins = { document: origin, foreignFrame: foreignOrigin }; save();
    await run(reference.extensionPath, false, origin, foreignOrigin);
    await run(root, true, origin, foreignOrigin);
    evidence.summary = { reference: 'object/query/state/foreign zero', owned: 'bounded source/sink observations', safeControls: 'zero', stopped: 'unchanged' }; save();
    console.log(JSON.stringify({ evidenceFile, summary: evidence.summary }));
}
main().catch(error => { evidence.error = error.stack || error.message; save(); console.error(error); process.exitCode = 1; }).finally(async () => {
    await browser?.close();
    for (const item of [server, foreignServer]) if (item) await new Promise(resolve => item.close(resolve));
    for (const folder of [temp, reference?.directory]) if (folder && path.resolve(folder).startsWith(path.resolve(os.tmpdir()) + path.sep) && /^cert-x-(?:iast-acquisition|security-reference)-/.test(path.basename(folder))) fs.rmSync(folder, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});
