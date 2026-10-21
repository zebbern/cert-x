// Native messaging host for the extension: gives the agent a shell and the local filesystem.
// Protocol: each message is a 4-byte little-endian length followed by UTF-8 JSON, on stdin/stdout.
const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawn } = require("child_process");

const MAX_REPLY = 900 * 1024;
const VERSION = 1;

function send(obj) {
  let json = JSON.stringify(obj);
  if (Buffer.byteLength(json) > MAX_REPLY) json = JSON.stringify({ id: obj.id, ok: false, error: "reply exceeded the 1 MB native messaging limit; request less data (max_chars / max_bytes / offset)" });
  const body = Buffer.from(json, "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length, 0);
  process.stdout.write(Buffer.concat([head, body]));
}

function resolvePath(p) {
  if (typeof p !== "string" || !p.trim()) throw new Error("path is required");
  let