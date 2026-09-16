/**
 * Extract the inlined console bundle from the built single-file HTML.
 *
 * Exists so the artifact that actually ships — the HTML — is the thing that
 * gets tested and verified, rather than the standalone bundle file that is
 * written alongside it. A build bug once corrupted only the inlined copy
 * (`$$` in a String.replace replacement), and every test still passed because
 * they all read the other file.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const DIST_HTML = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../dist/agent-inspector.html',
);

export function extractInlineBundle(htmlPath = DIST_HTML) {
  const html = fs.readFileSync(htmlPath, 'utf8');
  const opener = html.lastIndexOf('<script>');
  if (opener === -1) throw new Error('no inline script found in the built HTML');
  const start = opener + '<script>'.length;
  const end = html.indexOf('</script>', start);
  if (end === -1) throw new Error('the inline script is not terminated');
  // The build frames the bundle as `<script>\n<bundle>\n</script>`; strip that
  // framing so the extracted code is byte-identical to the standalone bundle.
  const raw = html.slice(start, end).replace(/^\n/, '').replace(/\n$/, '');
  return { code: raw, html };
}
