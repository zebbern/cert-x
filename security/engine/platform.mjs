// Late binding lets imported engines load before the shared resource broker is installed.
function platform(kind) {
  return new Proxy({}, { get(_target, key) {
    const api = globalThis.__certXSecurityResources?.[kind] || globalThis[kind];
    const value = api?.[key];
    return typeof value === 'function' ? value.bind(api) : value;
  }});
}
export const securityBrowser = platform('browser');
export const securityChrome = platform('chrome');
