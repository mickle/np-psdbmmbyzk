#!/usr/bin/env node
// Encrypt plaintext/ into vault.json + d/*.bin, or decrypt back.
// The password is read from DECK_PASSWORD and is never written to disk.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'plaintext');
const OUT = path.join(ROOT, 'd');
const OUT_TMP = path.join(ROOT, 'd.tmp');
const VAULT = path.join(ROOT, 'vault.json');
const VAULT_TMP = path.join(ROOT, 'vault.json.tmp');

// OWASP-style PBKDF2-HMAC-SHA256 count, kept high because passphrases may be short.
const ITERATIONS = 1_000_000;

const MIME = {
  html: 'text/html; charset=utf-8',
  css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8',
  json: 'application/json',
  txt: 'text/plain; charset=utf-8',
  pdf: 'application/pdf',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  webp: 'image/webp',
  gif: 'image/gif',
  svg: 'image/svg+xml',
  ico: 'image/x-icon',
};

function die(message) {
  console.error(message);
  process.exit(1);
}

function mimeFor(rel) {
  const ext = rel.split('.').pop().toLowerCase();
  return MIME[ext] || 'application/octet-stream';
}

function walk(dir) {
  const out = [];
  for (const name of fs.readdirSync(dir)) {
    if (name === '.DS_Store') continue;
    const p = path.join(dir, name);
    const st = fs.statSync(p);
    if (st.isDirectory()) out.push(...walk(p));
    else if (st.isFile()) out.push(p);
  }
  return out;
}

function safeRel(rel) {
  if (!rel || rel.startsWith('/') || rel.split('/').includes('..')) {
    die('Refusing unsafe path in manifest: ' + rel);
  }
  return rel;
}

function derive(password, salt, iterations = ITERATIONS) {
  return crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
}

function encryptBytes(key, plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  return Buffer.concat([iv, body]);
}

function decryptBytes(key, buf) {
  if (buf.length < 12 + 16) die('Ciphertext is truncated');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const data = buf.subarray(12, buf.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function decryptParts(key, iv, dataWithTag) {
  const tag = dataWithTag.subarray(dataWithTag.length - 16);
  const data = dataWithTag.subarray(0, dataWithTag.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function passwordFromEnv() {
  const password = process.env.DECK_PASSWORD;
  if (!password) die('Set DECK_PASSWORD in the environment. It is not stored in the repo.');
  return password;
}

function assertIgnored() {
  try {
    execSync('git check-ignore -q plaintext/index.html', { cwd: ROOT, stdio: 'ignore' });
  } catch {
    console.warn('Warning: plaintext/index.html is not gitignored.');
  }
}

async function assertWebCryptoCompatible(password, salt, key, fileBuf) {
  const subtle = globalThis.crypto.subtle;
  const km = await subtle.importKey('raw', Buffer.from(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    km,
    256
  );
  if (!Buffer.from(bits).equals(key)) die('PBKDF2 mismatch between Node and WebCrypto');
  const aes = await subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['decrypt']);
  const plain = await subtle.decrypt(
    { name: 'AES-GCM', iv: fileBuf.subarray(0, 12) },
    aes,
    fileBuf.subarray(12)
  );
  return Buffer.from(plain);
}

function encryptAll(password) {
  const indexPath = path.join(SRC, 'index.html');
  if (!fs.existsSync(indexPath)) {
    die('Missing plaintext/index.html. Put the deck source in plaintext/ (see README).');
  }
  const indexHtml = fs.readFileSync(indexPath, 'utf8');
  if (!indexHtml.includes('id="pf"') || !indexHtml.includes('noindex')) {
    die('plaintext/index.html does not look like the deck. Refusing to encrypt.');
  }

  const salt = crypto.randomBytes(16);
  const key = derive(password, salt);
  const files = walk(SRC)
    .map((file) => path.relative(SRC, file).split(path.sep).join('/'))
    .sort();

  fs.rmSync(OUT_TMP, { recursive: true, force: true });
  fs.mkdirSync(OUT_TMP, { recursive: true });

  const manifestFiles = {};
  let bytes = 0;
  for (const rel of files) {
    safeRel(rel);
    const plain = fs.readFileSync(path.join(SRC, rel));
    const enc = encryptBytes(key, plain);
    const back = decryptBytes(key, enc);
    if (!back.equals(plain)) die('Round trip failed for ' + rel);
    const id = crypto.randomBytes(16).toString('hex');
    fs.writeFileSync(path.join(OUT_TMP, id + '.bin'), enc);
    manifestFiles[rel] = { id, type: mimeFor(rel) };
    bytes += enc.length;
  }

  const manifest = Buffer.from(JSON.stringify({ v: 1, files: manifestFiles }));
  const mIv = crypto.randomBytes(12);
  const mCipher = crypto.createCipheriv('aes-256-gcm', key, mIv);
  const mEnc = Buffer.concat([mCipher.update(manifest), mCipher.final(), mCipher.getAuthTag()]);
  const mBack = decryptParts(key, mIv, mEnc);
  if (!mBack.equals(manifest)) die('Manifest round trip failed');

  const vault = {
    v: 1,
    kdf: 'PBKDF2',
    hash: 'SHA-256',
    iterations: ITERATIONS,
    salt: salt.toString('base64'),
    iv: mIv.toString('base64'),
    manifest: mEnc.toString('base64'),
  };
  if (JSON.stringify(vault).includes(password)) {
    die('Refusing to write vault metadata that contains the password. Re-run the build.');
  }

  fs.writeFileSync(VAULT_TMP, JSON.stringify(vault));
  fs.rmSync(OUT, { recursive: true, force: true });
  fs.renameSync(OUT_TMP, OUT);
  fs.renameSync(VAULT_TMP, VAULT);

  return { files, bytes, salt, key, manifestFiles };
}

function decryptAll(password, force) {
  if (!fs.existsSync(VAULT)) die('Missing vault.json');
  if (fs.existsSync(path.join(SRC, 'index.html')) && !force) {
    die('plaintext/index.html already exists. Pass --force to overwrite plaintext/.');
  }
  const vault = JSON.parse(fs.readFileSync(VAULT, 'utf8'));
  if (!Number.isInteger(vault.iterations) || vault.iterations < 100000 || vault.iterations > 5000000) {
    die('vault.json has an unexpected iteration count.');
  }
  const key = derive(password, Buffer.from(vault.salt, 'base64'), vault.iterations);
  let manifest;
  try {
    const raw = decryptParts(key, Buffer.from(vault.iv, 'base64'), Buffer.from(vault.manifest, 'base64'));
    manifest = JSON.parse(raw.toString('utf8'));
  } catch {
    die('Could not decrypt. The password does not match this vault.');
  }
  fs.mkdirSync(SRC, { recursive: true });
  let n = 0;
  for (const [rel, entry] of Object.entries(manifest.files)) {
    safeRel(rel);
    const buf = fs.readFileSync(path.join(OUT, entry.id + '.bin'));
    let plain;
    try {
      plain = decryptBytes(key, buf);
    } catch {
      die('Could not decrypt ' + rel);
    }
    const dest = path.join(SRC, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, plain);
    n += 1;
  }
  console.log('Decrypted ' + n + ' files into plaintext/. That directory is gitignored.');
}

const decrypt = process.argv.includes('--decrypt');
const force = process.argv.includes('--force');
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log('DECK_PASSWORD=… node scripts/build.mjs [--decrypt] [--force]');
  process.exit(0);
}

assertIgnored();
const password = passwordFromEnv();

if (decrypt) {
  decryptAll(password, force);
} else {
  const { files, bytes, salt, key, manifestFiles } = encryptAll(password);
  const sampleRel = manifestFiles['index.html'] ? 'index.html' : files[0];
  const sample = fs.readFileSync(path.join(OUT, manifestFiles[sampleRel].id + '.bin'));
  const viaWeb = await assertWebCryptoCompatible(password, salt, key, sample);
  const viaNode = decryptBytes(key, sample);
  if (!viaWeb.equals(viaNode)) die('WebCrypto decrypt did not match Node');
  console.log(
    'Encrypted ' + files.length + ' files (' + (bytes / 1024 / 1024).toFixed(1) +
    ' MB ciphertext). PBKDF2-SHA256 iterations: ' + ITERATIONS + '.'
  );
  console.log('Wrote vault.json and d/. plaintext/ was not modified and must stay untracked.');
}
