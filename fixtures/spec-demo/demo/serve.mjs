import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const root = process.argv[2] ?? 'demo/site';
const port = Number(process.argv[3] ?? 8787);

const server = http.createServer((req, res) => {
  const file = req.url === '/' ? '/index.html' : req.url.split('?')[0];
  const full = path.join(root, file);
  if (!fs.existsSync(full)) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(fs.readFileSync(full, 'utf8'));
});

server.listen(port, '127.0.0.1', () => {
  console.log(`demo site serving ${root} on http://127.0.0.1:${port}/`);
});
