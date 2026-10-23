// Initialize the two pinned, disposable DVWA comparison containers through
// DVWA's own setup flow. No public training service is modified.
const assert = require('node:assert/strict');

const origins = process.argv.slice(2);
assert.ok(origins.length > 0, 'Pass one or more local DVWA origins.');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const token = html => (html.match(/name=['"]user_token['"]\s+value=['"]([^'"]+)/i) || [])[1];

async function prepare(origin) {
  const url = new URL(origin);
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname), 'The setup fixture must be local.');
  const cookies = new Map();
  const absorb = response => {
    for (const line of response.headers.getSetCookie()) {
      const pair = line.split(';', 1)[0], index = pair.indexOf('=');
      if (index > 0) cookies.set(pair.slice(0, index), pair.slice(index + 1));
    }
  };
  const headers = () => ({ cookie:[...cookies].map(([key, value]) => key + '=' + value).join('; ') });
  let setup, created, setupResult;
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      setup = await fetch(new URL('/setup.php', url), { signal:AbortSignal.timeout(10000) });
      absorb(setup);
      if (setup.ok) {
        const setupToken = token(await setup.text());
        if (setupToken) {
          created = await fetch(new URL('/setup.php', url), {
            method:'POST', redirect:'manual', headers:{ ...headers(), 'content-type':'application/x-www-form-urlencoded' },
            body:new URLSearchParams({ create_db:'Create / Reset Database', user_token:setupToken }),
            signal:AbortSignal.timeout(30000)
          });
          absorb(created);setupResult = await created.text();
          if (created.status === 302 || /database has been created|setup successful|database setup/i.test(setupResult)) break;
        }
      }
    } catch {}
    await pause(1000);
  }
  assert.ok(created?.status === 302 || /database has been created|setup successful|database setup/i.test(setupResult || ''), 'DVWA database setup did not report success.');
  const login = await fetch(new URL('/login.php', url), { headers:headers(), signal:AbortSignal.timeout(10000) });
  absorb(login);
  const loginHtml = await login.text(), loginToken = token(loginHtml);
  assert.ok(login.ok && loginToken, 'DVWA login form did not become ready after setup.');
  const signedIn = await fetch(new URL('/login.php', url), {
    method:'POST', redirect:'manual', headers:{ ...headers(), 'content-type':'application/x-www-form-urlencoded' },
    body:new URLSearchParams({ username:'admin', password:'password', Login:'Login', user_token:loginToken }),
    signal:AbortSignal.timeout(10000)
  });
  absorb(signedIn);
  assert.ok(signedIn.status === 302 && /index\.php/.test(signedIn.headers.get('location') || ''), 'Default DVWA login did not succeed.');
  const home = await fetch(new URL('/index.php', url), { headers:headers(), signal:AbortSignal.timeout(10000) });
  const homeText = await home.text();
  assert.ok(home.ok && /Damn Vulnerable Web Application/i.test(homeText), 'Authenticated DVWA home did not load.');
  console.log(JSON.stringify({ origin:url.origin, databaseReady:true, loginVerified:true }));
}

(async () => { for (const origin of origins) await prepare(origin); })().catch(error => { console.error(error.message); process.exitCode = 1; });
