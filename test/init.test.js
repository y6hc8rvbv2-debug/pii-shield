import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { init } from '../bin/init.js';
import { scanProject } from '../src/scan.js';

const newApp = () => mkdtempSync(join(tmpdir(), 'pii-init-'));
const read = (root, rel) => readFileSync(join(root, rel), 'utf8');

test('新しいアプリに必要なファイル一式を作る', () => {
  const root = newApp();
  init(root, { install: false });
  for (const rel of ['package.json', 'lib/pii-shield.js', '.env', '.env.example', '.gitignore', '.github/workflows/pii-shield-check.yml', 'CLAUDE.md']) {
    assert.ok(existsSync(join(root, rel)), `${rel} がない`);
  }
  assert.match(read(root, '.env'), /^PII_KEY_V1=[A-Za-z0-9+/]{43}=\nPII_INDEX_KEY=[A-Za-z0-9+/]{43}=\n$/);
  assert.match(read(root, '.gitignore'), /^\.env$/m);
  assert.match(read(root, 'CLAUDE.md'), /shield\.protect/);
  assert.equal(JSON.parse(read(root, 'package.json')).scripts['check:pii'], 'pii-shield-check');
  // 作ったものが「必ず守ってほしいこと」に違反していない
  assert.deepEqual(scanProject(root).findings, []);
});

test('2回実行しても既存のファイルや鍵を壊さない', () => {
  const root = newApp();
  writeFileSync(join(root, 'CLAUDE.md'), '# 既存のルール\n');
  writeFileSync(join(root, '.gitignore'), 'dist/\n');
  init(root, { install: false });
  const env = read(root, '.env');
  const { done } = init(root, { install: false });
  assert.deepEqual(done, []);
  assert.equal(read(root, '.env'), env); // 鍵が作り直されない（作り直すと既存データが読めなくなる）
  assert.match(read(root, 'CLAUDE.md'), /^# 既存のルール\n/);
  assert.equal(read(root, 'CLAUDE.md').match(/<!-- pii-shield -->/g).length, 1);
  assert.equal(read(root, '.gitignore'), 'dist/\n.env\nnode_modules/\n');
});

test('CommonJS 形式のアプリでは .mjs で設定ファイルを作る', () => {
  const root = newApp();
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'old-app' }));
  const { configPath } = init(root, { install: false });
  assert.equal(configPath, 'lib/pii-shield.mjs');
  assert.ok(existsSync(join(root, 'lib/pii-shield.mjs')));
});
