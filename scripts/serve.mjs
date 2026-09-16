#!/usr/bin/env node
/**
 * Local development server for the console.
 *
 * Only needed because ES modules cannot be imported over file://. The
 * deliverable that always works offline is dist/agent-inspector.html, which
 * is a single self-contained file with everything inlined.
 *
 * Binds to loopback only, serves read-only, and refuses path traversal.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.PORT ?? 8788);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
};

const server = http.createServer((req, res) => {
  const urlPath = decodeURIComponent((req.url ?? '/').split('?')[0]);
  const rel = urlPath === '/' ? 'app/index.html' : urlPath.replace(/^\/+/, '');
  const full = path.resolve(ROOT, rel);

  if (!full.startsWith(ROOT)) {
    res.writeHead(403, { 'content-type': 'text/plain' });
    res.end('forbidden');
    return;
  }
  if (!fs.existsSync(full) || fs.statSync(full).isDirectory()) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
    return;
  }

  const ext = path.extname(full).toLowerCase();
  res.writeHead(200, {
    'content-type': TYPES[ext] ?? 'application/octet-stream',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  fs.createReadStream(full).pipe(res);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Agent Inspector console: http://127.0.0.1:${PORT}/  (loopback only, read-only)`);
  console.log(`Static single-file build:  ${path.join(ROOT, 'dist', 'agent-inspector.html')}`);
});
