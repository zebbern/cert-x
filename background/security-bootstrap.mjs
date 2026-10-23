import { createSecurityResources } from '../security/resources.mjs';
import { createSecurityRuntime } from '../security/runtime.mjs';
import { createSecurityService } from '../security/service.mjs';
import { createCompatibilityRuntime } from '../security/compat/runtime.mjs';

const resources = createSecurityResources(chrome);
globalThis.__certXSecurityResources = resources;
globalThis.certXSecurityResources = resources;
globalThis.certXBrowserChrome = resources.forOwner('browser');
const runtime = createSecurityRuntime({ resources });
globalThis.certXSecurity = createSecurityService(runtime);
globalThis.certXSecurityCompatibilityReady = Promise.resolve(runtime.ready).then(() => {
  const compatibility = createCompatibilityRuntime(runtime.app, resources);
  globalThis.certXSecurityCompatibility = compatibility;
  return compatibility.ready.then(() => compatibility);
});
globalThis.certXSecurityCompatibilityReady.catch(error => console.error('Security compatibility initialization:', error));
globalThis.certXSecurity.ready.catch(error => console.error('Security initialization:', error));
