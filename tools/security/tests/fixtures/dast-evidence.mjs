// Shared explicit HTTP evidence fixtures; no detector implementation is duplicated here.
export const reply=(body='',headers=[],statusCode=200)=>({body,headers,statusCode,length:body.length,isHttps:true});
export const header=(name,value)=>({name,value});
export const fixtures={
 sql_injection:{attack:reply('You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version')},
 os_command_injection:{attack:reply('root:x:0:0:root:/root:/bin/bash')},
 xss:{attack:reply('<script>alert(987101)</script>')},
 version_control_exposure:{attack:reply('Index of /.git')},
 headers:{original:reply('normal'),negativeOriginal:reply('normal',[header('Content-Security-Policy',"default-src 'self'")])},
 sensitive_data_exposure:{original:reply('Credit Card Number 4111111111111111')},
 websocket_security:{original:reply('new WebSocket("ws://fixture.test/socket")')},
 recon_sourcemaps_debug:{url:'https://fixture.test/app.js',original:reply('//# sourceMappingURL=app.js.map')},
 recon_error_stacktraces:{original:reply('Error: fixture\n    at handler (node_modules/express/router.js:10:20)')},
 recon_client_config_secrets:{original:reply('-----BEGIN PRIVATE KEY-----')},
 recon_api_docs_specs:{original:reply('<title>Swagger UI</title>')},
 recon_well_known_metadata:{url:'https://fixture.test/.well-known/security.txt'},
 recon_tokens_in_url:{url:'https://fixture.test/?access_token=abcdefgh'},
 recon_parameter_leads:{url:'https://fixture.test/?next=https://example.test',originalBody:{text:'next=https://example.test'}},
 recon_internal_hosts_env_hints:{original:reply('upstream 192.168.1.20')},
 recon_cors_posture:{original:reply('normal',[header('Access-Control-Allow-Origin','https://fixture.test')])},
 recon_cache_privacy:{original:reply('private data',[header('Set-Cookie','test=fixture'),header('Cache-Control','public, max-age=60')]),negativeOriginal:reply('private data',[header('Set-Cookie','test=fixture'),header('Cache-Control','no-store')])},
 recon_interesting_endpoints:{url:'https://fixture.test/admin/'},
 jsonp_callback_injection:{url:'https://fixture.test/?callback=initial',attack:reply('ptkJsonpCallback({"ok":true})',[header('Content-Type','application/javascript')])},
 open_redirect:{url:'https://fixture.test/?next=/home',attack:reply('',[header('Location','https://example.com')],302)},
 cve_2025_55182_react_rsc:{original:reply('react-server'),attack:reply('digest',[header('Content-Type','text/x-component')],500)},
 cve_2015_1635:{attack:reply('HTTP Error 416 The requested range is not satisfiable',[header('Server','Microsoft-IIS')],416)},
 cve_2018_20062:{attack:reply('PHP Extension PHP Version ThinkPHP')},
 cve_2019_10692:{attack:reply('{"user_login":"test","user_pass":"fixture","user_nicename":"test"}',[header('Content-Type','application/json')])},
 cve_2020_14092:{attack:reply('{"user_login":"test","user_email":"fixture@example.test","user_pass":"fixture","user_activation_key":""}',[header('Content-Type','text/html')])},
 cve_2020_17530:{attack:reply('root:x:0:0:fixture')},
 cve_2021_28918:{attack:reply('Apache Server Status Server Version')},
 cve_2022_47945:{attack:reply('Call Stack <div class="trace">',[],500)},
 cve_2023_34598:{attack:reply('phpMyAdmin SQL Dump gibbon')},
 cve_2023_5991:{attack:reply('root:x:0:0:fixture',[header('Content-Disposition','filename=/etc/passwd')])},
 cve_2022_1970_cve_2024_27954:{attack:reply('{"link":"file:///etc/passwd"}\nroot:x:0:0:fixture')}
};
export function buildSchemas({ptk_request,engine},module,fixture,positive,attackIndex=0){
 const url=positive?(fixture.url||'https://fixture.test/?q=fixture'):'https://fixture.test/?q=fixture';
 const original=ptk_request.parseRawRequest(`GET ${url} HTTP/1.1\r\nHost: fixture.test\r\n\r\n`);
 original.response=positive?(fixture.original||reply('normal')):(fixture.negativeOriginal||reply('normal'));
 if(positive&&fixture.originalBody)original.request.body=fixture.originalBody;
 const prepared=module.prepareAttack(module.attacks[attackIndex]);
 const executed=engine._enrichAttackPayload(module.buildAttack(structuredClone(original),prepared),module,prepared);
 executed.response=positive?(fixture.attack||structuredClone(original.response)):reply('normal',[header('Content-Security-Policy',"default-src 'self'")]);
 return {executed,original};
}
