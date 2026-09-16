#!/usr/bin/env node
// FIXTURE — synthetic ContentPulse-like entrypoint.
// Static analysis target only; the Inspector never executes this file.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import cron from 'node-cron';
import nodemailer from 'nodemailer';
import { loadConfig } from '../src/config.js';
import { fetchContent } from '../src/http.js';
import { openStore } from '../src/store.js';

const cfg = loadConfig('demo/sources.yaml');

// Reads configuration and credentials from the environment.
const smtpHost = process.env.SMTP_HOST;
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const digestTo = process.env.DIGEST_TO;

async function deliver(webhookUrl, digest) {
  const res = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(digest),
  });
  return res.status;
}

async function sendMail(digest) {
  const transport = nodemailer.createTransport({
    host: smtpHost,
    port: Number(process.env.SMTP_PORT ?? 587),
    auth: { user: smtpUser, pass: smtpPass },
  });
  await transport.sendMail({ from: smtpUser, to: digestTo, subject: 'digest', text: digest });
}

export async function runOnce() {
  const store = openStore(cfg.db);
  for (const source of cfg.sources) {
    const body = await fetchContent(source.url);
    store.put(source.name, body);
  }
  fs.writeFileSync(path.join(cfg.output, 'latest.md'), '# digest\n');
}

export function startWatcher() {
  cron.schedule('0 9 * * *', () => { runOnce(); });
}

export function startParserService(port = 8080) {
  const server = http.createServer((req, res) => { res.end('ok'); });
  server.listen(port, '127.0.0.1');
}

startWatcher();
runOnce();
