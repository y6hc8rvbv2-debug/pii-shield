#!/usr/bin/env node
// 使い方: npx pii-shield-check [調べるフォルダ]  （省略時は今いるフォルダ）
// 違反（エラー）があると終了コード 1 で終わるので、GitHub Actions や git の commit 前チェックに組み込めます。
// --strict を付けると、警告（warning）でも終了コード 1 になります。
import { resolve } from 'node:path';
import { scanProject } from '../src/scan.js';

const args = process.argv.slice(2);
const strict = args.includes('--strict');
const root = resolve(args.find((a) => !a.startsWith('--')) ?? '.');
const knownKeys = Object.entries(process.env)
  .filter(([name]) => /^PII_(KEY\w*|INDEX_KEY)$/.test(name))
  .map(([, value]) => value);

const { findings } = scanProject(root, { knownKeys });
const errors = findings.filter((f) => f.level === 'error');
const warnings = findings.filter((f) => f.level === 'warning');

console.log(`PII Shield セキュリティチェック: ${root}\n`);
for (const f of findings) {
  const icon = f.level === 'error' ? '❌ 違反' : '⚠️  注意';
  console.log(`${icon} [必ず守ってほしいこと ルール${f.rule}] ${f.file}${f.line ? `:${f.line}` : ''}\n   ${f.message}\n`);
}
if (findings.length === 0) console.log('✅ 違反は見つかりませんでした。');
else console.log(`結果: 違反 ${errors.length} 件 / 注意 ${warnings.length} 件`);
console.log('（誤検知の行には「pii-shield-ignore」とコメントを書くと対象外になります）');

process.exitCode = errors.length > 0 || (strict && warnings.length > 0) ? 1 : 0;
