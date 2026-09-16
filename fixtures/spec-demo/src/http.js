// FIXTURE module — static analysis target.
export async function fetchContent(url) {
  const res = await fetch(url, { headers: { 'user-agent': 'contentpulse-fixture/0.1' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}
