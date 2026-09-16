// FIXTURE module — static analysis target.
import fs from 'node:fs';
import path from 'node:path';

export function openStore(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const state = new Map();
  return {
    put(key, value) { state.set(key, value); },
    get(key) { return state.get(key); },
    flush() { fs.writeFileSync(file, JSON.stringify([...state.entries()])); },
  };
}
