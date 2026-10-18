import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { ShieldSecurityError, createShield, generateKey } from '../src/index.js';
import { checkKeyHandling, detectClientRuntime } from '../src/safety.js';
import { scanProject } from '../src/scan.js';

const schema = { email: { mask: 'email' } };

// ---- アプリ起動時のチェック ----

test('ルール1: 環境変数以外から渡された鍵（コード直書きの疑い）は警告される', () => {
  const warnings = [];
  createShield({ keys: { 1: generateKey() }, activeKeyVersion: 1, indexKey: generateKey(), schema, onSecurityWarning: (w) => warnings.push(w) });
  assert.equal(warnings.length, 2);
  assert.ok(warnings.every((w) => w.rule === 1 && w.code === 'KEY_NOT_FROM_ENV'));
});

test('ルール1: 環境変数から読んだ鍵なら警告なし', () => {
  const env = { PII_KEY_V1: generateKey(), PII_INDEX_KEY: generateKey() };
  const keys = [{ label: 'keys[1]', value: env.PII_KEY_V1 }, { label: 'indexKey', value: env.PII_INDEX_KEY }];
  assert.deepEqual(checkKeyHandling({ keys, env }), []);
});

test("鍵管理サービス利用時（keySource: 'kms'）は警告なし", () => {
  const warnings = [];
  createShield({ keys: { 1: generateKey() }, activeKeyVersion: 1, indexKey: generateKey(), schema, keySource: 'kms', onSecurityWarning: (w) => warnings.push(w) });
  assert.deepEqual(warnings, []);
});

test('ルール1: フロントエンドに公開される環境変数（NEXT_PUBLIC_ 等）に鍵があると警告', () => {
  const key = generateKey();
  const warnings = checkKeyHandling({ keys: [{ label: 'keys[1]', value: key }], env: { NEXT_PUBLIC_PII_KEY: key } });
  assert.deepEqual(warnings.map((w) => w.code), ['KEY_IN_PUBLIC_ENV']);
});

test('ルール2: 本番で鍵とDB接続情報が同じ環境変数にあると警告', () => {
  const key = generateKey();
  const keys = [{ label: 'keys[1]', value: key }];
  const env = { PII_KEY_V1: key, DATABASE_URL: 'postgres://u:p@db/app', NODE_ENV: 'production' };
  assert.deepEqual(checkKeyHandling({ keys, env }).map((w) => w.rule), [2]);
  assert.deepEqual(checkKeyHandling({ keys, env, keySource: 'kms' }), []);
  assert.deepEqual(checkKeyHandling({ keys, env: { ...env, NODE_ENV: 'development' } }), []);
});

test('strictSecurity: true なら警告ではなくエラーで止まる', () => {
  assert.throws(
    () => createShield({ keys: { 1: generateKey() }, activeKeyVersion: 1, indexKey: generateKey(), schema, strictSecurity: true }),
    (err) => err instanceof ShieldSecurityError && err.warnings.length === 2,
  );
});

test('ルール1: ブラウザ・スマホアプリ内での利用を検知する', () => {
  assert.equal(detectClientRuntime({ window: {}, document: {} }), 'ブラウザ（フロントエンド）');
  assert.equal(detectClientRuntime({ navigator: { product: 'ReactNative' } }), 'スマホアプリ（React Native）');
  assert.equal(detectClientRuntime({}), null);
});

// ---- 公開前のファイルチェック ----

function project(files) {
  const root = mkdtempSync(join(tmpdir(), 'pii-scan-'));
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return root;
}

const summary = (root, opts) => scanProject(root, opts).findings.map((f) => `${f.level}:${f.rule}:${f.file}`).sort();

test('正しい使い方なら違反なし', () => {
  const root = project({
    'server/shield.js': "import { createShield } from 'pii-shield';\ncreateShield({ keys: { 1: process.env.PII_KEY_V1 }, indexKey: process.env.PII_INDEX_KEY });",
    '.gitignore': '.env\n',
    '.env': `PII_KEY_V1=${generateKey()}\n`,
  });
  assert.deepEqual(summary(root), []);
});

test('ルール1: ソースコードへの鍵の直書きを見つける', () => {
  const root = project({ 'server/shield.js': `createShield({ keys: { 1: '${generateKey()}' } });` });
  assert.deepEqual(summary(root), ['error:1:server/shield.js']);
});

test('ルール1: 画面側・スマホアプリ側での読み込みを見つける', () => {
  const root = project({
    'frontend/login.js': "import { createShield } from 'pii-shield';",
    'app/page.jsx': "'use client';\nimport { createShield } from 'pii-shield';",
    'server/ok.js': "import { createShield } from 'pii-shield';",
  });
  assert.deepEqual(summary(root), ['error:1:app/page.jsx', 'error:1:frontend/login.js']);
});

test('ルール1: 実際の鍵の値がビルド済みファイル等に紛れ込んでいたら見つける', () => {
  const key = generateKey();
  const root = project({ 'dist/bundle.js': `var a="${key}";` });
  assert.deepEqual(summary(root), []); // 変数名がなくても…
  assert.deepEqual(summary(root, { knownKeys: [key] }), ['error:1:dist/bundle.js']); // 実際の鍵を渡せば見つかる
});

test('ルール1: .env が .gitignore に入っていなければ違反', () => {
  const root = project({ '.env': `PII_KEY_V1=${generateKey()}\n` });
  assert.deepEqual(summary(root), ['error:1:.env']);
});

test('ルール2: 鍵とDB接続情報が同じ .env／鍵がDB関連ファイルにある', () => {
  const root = project({
    '.gitignore': '.env\n',
    '.env': `PII_KEY_V1=${generateKey()}\nDATABASE_URL=postgres://u:p@db/app\n`,
    'migrations/001_seed.sql': `-- PII_KEY_V1=${generateKey()}\nINSERT INTO users VALUES (1);`,
  });
  assert.deepEqual(summary(root), ['error:2:migrations/001_seed.sql', 'warning:2:.env']);
});

test('pii-shield-ignore を書いた行は対象外', () => {
  const root = project({ 'server/x.js': `const PII_KEY_V1 = '${generateKey()}'; // pii-shield-ignore テスト用` });
  assert.deepEqual(summary(root), []);
});
