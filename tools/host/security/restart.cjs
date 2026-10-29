'use strict';
const path=require('node:path'),{execFile}=require('node:child_process'),{promisify}=require('node:util');
const run=promisify(execFile);
function windowsArguments(commandLine) {
 const values=[];let index=0;
 while(index<commandLine.length){while(/\s/.test(commandLine[index]||'')&&index<commandLine.length)index++;if(index>=commandLine.length)break;let value='',quoted=false;
  while(index<commandLine.length){if(!quoted&&/\s/.test(commandLine[index]))break;
   if(commandLine[index]==='\\'){let count=0;while(commandLine[index]==='\\'){count++;index++;}if(commandLine[index]==='"'){value+='\\'.repeat(Math.floor(count/2));if(count%2){value+='"';index++;}else{quoted=!quoted;index++;}}else value+='\\'.repeat(count);continue;}
   if(commandLine[index]==='"'){quoted=!quoted;index++;continue;}value+=commandLine[index++];
  }if(quoted)throw Error('Unbalanced process command line');values.push(value);
 }return values;
}
const equalPath=(a,b)=>typeof a==='string'&&typeof b==='string'&&path.resolve(a).toLowerCase()===path.resolve(b).toLowerCase();
function verifyIdentity(processInfo,{pid,script,root,executable=process.execPath}) {
 if(processInfo?.ProcessId!==pid||!equalPath(processInfo.ExecutablePath,executable))return false;
 const args=windowsArguments(processInfo.CommandLine||'');
 return args.length===3&&equalPath(args[0],executable)&&equalPath(args[1],script)&&equalPath(args[2],root);
}
async function powershell(script){return run('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{windowsHide:true,timeout:15000,maxBuffer:65536});}
async function stopLegacyDaemon(descriptor,{root,script,authenticated}) {
 if(authenticated!==true||!Number.isSafeInteger(descriptor?.pid)||descriptor.pid<=0)throw Error('Legacy runtime ownership could not be verified. Stop local testing and restart Windows to finish updating.');
 if(process.platform!=='win32')throw Error('Legacy runtime restart requires verified Windows process identity. Restart the computer to finish updating.');
 let info;try{const {stdout}=await powershell(`$item=Get-CimInstance Win32_Process -Filter "ProcessId = ${descriptor.pid}"; if (!$item) { throw 'Process missing' }; [pscustomobject]@{ProcessId=[int]$item.ProcessId;ExecutablePath=$item.ExecutablePath;CommandLine=$item.CommandLine;CreationDate=$item.CreationDate.ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress`);info=JSON.parse(stdout.trim());}catch{throw Error('Legacy runtime ownership could not be verified. Stop local testing and restart Windows to finish updating.');}
 if(!verifyIdentity(info,{pid:descriptor.pid,script,root}))throw Error('Legacy runtime process identity does not match this installation. Restart Windows to finish updating; no process was terminated.');
 const encoded=Buffer.from(JSON.stringify(info),'utf8').toString('base64');
 // Hold the verified process handle through the final identity check and tree
 // termination so a stale descriptor cannot target an unrelated reused PID.
 await powershell(`$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')) | ConvertFrom-Json; $process=[Diagnostics.Process]::GetProcessById([int]$expected.ProcessId); try { $null=$process.Handle; $actual=Get-CimInstance Win32_Process -Filter "ProcessId = $($expected.ProcessId)"; if (!$actual -or $actual.CommandLine -cne $expected.CommandLine -or $actual.ExecutablePath -ine $expected.ExecutablePath -or $actual.CreationDate.ToUniversalTime().ToString('o') -cne $expected.CreationDate) { throw 'Runtime identity changed; no process was terminated' }; & taskkill.exe /PID $expected.ProcessId /T /F | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'Runtime termination was not confirmed' }; if (!$process.WaitForExit(5000)) { throw 'Runtime did not exit' } } finally { $process.Dispose() }`);
 return {restarted:true,legacy:true,stoppedActiveTesting:true};
}
module.exports={stopLegacyDaemon,verifyIdentity,windowsArguments};
