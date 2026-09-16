// FIXTURE module — static analysis target.
import fs from 'node:fs';
import path from 'node:path';

export function loadConfig(file) {
  const raw = fs.readFileSync(file, 'utf8');
  return {
    db: process.env.CONTENTPULSE_DB ?? '.contentpulse/contentpulse.db',
    output: process.env.CONTENTPULSE_OUTPUT ?? '.contentpulse/out',
    sources: [{ name: 'fixture', url: 'http://127.0.0.1:8787/' }],
    _raw: raw,
    _dir: path.dirname(file),
  };
}
