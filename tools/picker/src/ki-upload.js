// Use the already-attached tab debugger for CSS file inputs. The generic
// command wrapper can stall after a browser-created download when resolving a
// second DOM.getDocument; upload must return a bounded result to the agent.
// Agent-created payloads can avoid the download/debugger path entirely.
pP.upload.description = 'Select files in an input[type=file] on the working page. Use exactly one source: attachments from user-supplied attachment IDs, files from absolute user-provided paths, or generated:{filename,content,mimeType?} for a small agent-created text file. Generated files need a CSS selector and do not require a local download. Other sources accept the input ref or selector from snapshot.';
pP.upload.parameters.properties.generated = { type:'object', description:'Agent-created text file for this page; no local path or prior save_file call.',
  properties:{ filename:{type:'string'}, content:{type:'string'}, mimeType:{type:'string'} }, required:['filename','content'], additionalProperties:false };
var kiUploadOriginalExecute = Ei.prototype.execute;
Ei.prototype.execute = async function(args) {
  if (!Object.hasOwn(args, 'generated')) return kiUploadOriginalExecute.call(this, args);
  var generated = args.generated, selector = args.selector;
  if (!generated || typeof generated !== 'object' || Array.isArray(generated) || typeof generated.filename !== 'string' || !generated.filename || generated.filename.length > 180 || /[\\/:\x00-\x1f]/.test(generated.filename)) throw Error('upload: generated.filename must be a plain file name.');
  if (typeof generated.content !== 'string' || new TextEncoder().encode(generated.content).length > 256 * 1024) throw Error('upload: generated.content must be text up to 256 KiB.');
  if (generated.mimeType != null && (typeof generated.mimeType !== 'string' || generated.mimeType.length > 150)) throw Error('upload: generated.mimeType is invalid.');
  if (typeof selector !== 'string' || !selector) throw Error('upload: generated files require a CSS selector for an input[type=file].');
  if (!Number.isInteger(args._tabId)) throw Error('upload: choose a target browser tab.');
  var tab = await chrome.tabs.get(args._tabId);
  if (!/^https?:\/\//.test(tab.url || '')) throw Error('upload: select an HTTP(S) page.');
  var injected = await kiUploadBounded(chrome.scripting.executeScript({ target:{ tabId:tab.id }, world:'ISOLATED',
    func:({ selector, filename, content, mimeType }) => {
      const input = document.querySelector(selector);
      if (!(input instanceof HTMLInputElement) || input.type !== 'file') return { error:'The selector did not match a file input.' };
      const file = new File([content], filename, { type:mimeType || 'application/octet-stream' });
      const transfer = new DataTransfer(); transfer.items.add(file); input.files = transfer.files;
      input.dispatchEvent(new Event('input', { bubbles:true })); input.dispatchEvent(new Event('change', { bubbles:true }));
      return { url:location.href, name:input.files?.[0]?.name, size:input.files?.[0]?.size, count:input.files?.length };
    }, args:[{ selector, filename:generated.filename, content:generated.content, mimeType:generated.mimeType || null }]
  }), 'generated file selection');
  var selected = injected?.[0]?.result;
  if (selected?.error) throw Error('upload: ' + selected.error);
  if (!selected || selected.count !== 1 || selected.name !== generated.filename || selected.size !== new TextEncoder().encode(generated.content).length || new URL(selected.url).origin !== new URL(tab.url).origin) throw Error('upload: generated file selection could not be verified.');
  return { success:true, selector, source:'generated', fileCount:1, selectedFiles:[{ name:selected.name, size:selected.size }] };
};
var kiUploadOriginalSetInputPaths = Ei.prototype.setInputPaths;
function kiUploadBounded(promise, method) {
  var timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(Error("upload: " + method + " timed out. Check the target tab and retry with a fresh file input selector.")), 15000);
  })]).finally(() => clearTimeout(timer));
}
Ei.prototype.setInputPaths = async function(tabId, selector, files) {
  if (ir(selector) || me(selector)) return kiUploadBounded(kiUploadOriginalSetInputPaths.call(this, tabId, selector, files), "file input resolution");
  if (typeof selector !== "string" || !selector) throw Error("upload: choose a file input selector.");
  var target = { tabId }, send = (method, params = {}) => kiUploadBounded(chrome.debugger.sendCommand(target, method, params), method);
  var found = await send("Runtime.evaluate", { expression: "document.querySelector(" + JSON.stringify(selector) + ")", returnByValue: false });
  if (found?.exceptionDetails || !found?.result?.objectId) throw Error("upload: element not found: " + selector);
  var selectedFiles;
  try {
    await send("DOM.setFileInputFiles", { objectId: found.result.objectId, files });
    var selection = await send("Runtime.callFunctionOn", { objectId: found.result.objectId,
      functionDeclaration: "function(){return Array.from(this.files||[]).map(file=>({name:file.name,size:file.size}))}", returnByValue: true });
    selectedFiles = selection?.result?.value;
    if (!Array.isArray(selectedFiles) || selectedFiles.length !== files.length) throw Error("upload: file input did not retain the selected files.");
  }
  finally { await kiUploadBounded(chrome.debugger.sendCommand(target, "Runtime.releaseObject", { objectId: found.result.objectId }), "Runtime.releaseObject").catch(() => {}); }
  return { success: true, selector, fileCount: files.length, files, selectedFiles,
    ...(selectedFiles.some(file => file.size === 0) ? { warning: "At least one selected file has zero bytes. Verify that its source path exists or that an empty file was intended." } : {}) };
};
