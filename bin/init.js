// 新しいアプリに PII Shield を組み込むためのセットアップ
// 使い方（アプリのフォルダで実行）: npx github:y6hc8rvbv2-debug/pii-shield init
// 既にあるファイルは上書きしません（.env / .gitignore / CLAUDE.md は必要な行だけ追記します）。
import { execSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { generateKey } from '../src/index.js';

export const PACKAGE_SOURCE = 'github:y6hc8rvbv2-debug/pii-shield';
const MARKER = '<!-- pii-shield -->';

const shieldConfig = `// 個人情報を守る設定（PII Shield）
// ⚠ このファイルはサーバー側のコードからだけ読み込むこと（画面側・スマホアプリでは使わない）
import { createShield } from 'pii-shield';

// .env を自動で読み込まない環境（素の Node.js）向け。Next.js や Vercel などは自動で読み込む
if (!process.env.PII_KEY_V1 && typeof process.loadEnvFile === 'function') {
  try {
    process.loadEnvFile();
  } catch {
    // .env が無い場合は、サーバーに設定された環境変数をそのまま使う
  }
}

export const shield = createShield({
  keys: { 1: process.env.PII_KEY_V1 },
  activeKeyVersion: 1,
  indexKey: process.env.PII_INDEX_KEY,
  // 守りたい個人情報の項目。アプリに合わせて追加・削除する
  schema: {
    email: { index: 'email', mask: 'email' },
    phone: { index: 'phone', mask: 'phone' },
    name: { mask: 'name' },
    address: { mask: 'address' },
  },
  // 本番では「必ず守ってほしいこと」に違反していたら起動を止める
  strictSecurity: process.env.NODE_ENV === 'production',
});
`;

const workflow = `# GitHub にコードを上げるたびに「必ず守ってほしいこと」の違反がないか自動で確認する
name: pii-shield-check
on: [push, pull_request]
jobs:
  pii-shield-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install --no-audit --no-fund
      - run: npx pii-shield-check
`;

const claudeRules = (configPath) => `
${MARKER}
## 個人情報の扱い（PII Shield）
このアプリは個人情報保護モジュール PII Shield（https://github.com/y6hc8rvbv2-debug/pii-shield）を使う。コードを書くときは次を必ず守ること。

- 利用者の個人情報（氏名・メール・電話・住所・生年月日・カード番号など）は、必ず \`${configPath}\` の \`shield\` を通して扱う
  - 保存前に \`shield.protect(record)\`、メール等での検索は \`shield.indexOf(項目, 値)\`
  - API応答・一覧画面は \`shield.toPublic(record)\`（マスク済みの値だけ返す）
  - 平文が必要な本人向け画面だけ \`shield.reveal(record, { actor: ログイン中の利用者ID })\`
- パスワードは \`shield.hashPassword()\` / \`shield.verifyPassword()\` を使い、平文で保存しない
- 新しい個人情報の項目を追加したら \`${configPath}\` の schema にも追加する
- PII Shield と鍵はサーバー側のコードでだけ使う。フロントエンド・スマホアプリのコードでは読み込まない
- 鍵（PII_KEY_V1 / PII_INDEX_KEY）はコードに書かず、環境変数か鍵管理サービスから読む。\`.env\` は Git に入れない
- 変更後は \`npx pii-shield-check\` を実行し、違反がないことを確認する
`;

export function init(root, { install = true, log = console.log } = {}) {
  const done = [];
  const skipped = [];
  const write = (rel, content) => {
    const file = join(root, rel);
    if (existsSync(file)) return skipped.push(`${rel}（既にあるため変更なし）`);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, content);
    done.push(`${rel} を作成`);
  };
  const appendLines = (rel, lines, what) => {
    const file = join(root, rel);
    const current = existsSync(file) ? readFileSync(file, 'utf8') : '';
    const missing = lines.filter((l) => !current.split(/\r?\n/).some((c) => c.split('=')[0].trim() === l.split('=')[0].trim()));
    if (missing.length === 0) return skipped.push(`${rel}（${what}は設定済み）`);
    const sep = current && !current.endsWith('\n') ? '\n' : '';
    appendFileSync(file, sep + missing.join('\n') + '\n');
    done.push(`${rel} に${what}を追加`);
  };

  // package.json（無ければ作る）
  const pkgPath = join(root, 'package.json');
  if (!existsSync(pkgPath)) {
    writeFileSync(pkgPath, JSON.stringify({ name: basename(root), private: true, type: 'module' }, null, 2) + '\n');
    done.push('package.json を作成');
  }
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  const isModule = pkg.type === 'module';
  const configPath = isModule ? 'lib/pii-shield.js' : 'lib/pii-shield.mjs';

  // 1. 設定ファイル
  write(configPath, shieldConfig);

  // 2. 鍵（.env）と、その見本（.env.example）
  appendLines('.env', [`PII_KEY_V1=${generateKey()}`, `PII_INDEX_KEY=${generateKey()}`], '暗号鍵');
  appendLines('.env.example', ['PII_KEY_V1=', 'PII_INDEX_KEY='], '鍵の項目名');

  // 3. .env を Git に入れない
  appendLines('.gitignore', ['.env', 'node_modules/'], '.env の除外設定');

  // 4. GitHub での自動チェック
  write('.github/workflows/pii-shield-check.yml', workflow);

  // 5. Claude 向けのルール（Claude がこのアプリを作業するときに自動で読む）
  const claudePath = join(root, 'CLAUDE.md');
  const claudeCurrent = existsSync(claudePath) ? readFileSync(claudePath, 'utf8') : '';
  if (claudeCurrent.includes(MARKER)) {
    skipped.push('CLAUDE.md（ルールは記載済み）');
  } else {
    appendFileSync(claudePath, (claudeCurrent ? '' : '# このアプリの開発ルール\n') + claudeRules(configPath));
    done.push('CLAUDE.md に個人情報の扱いルールを追加');
  }

  // 6. npm スクリプト
  pkg.scripts ??= {};
  if (!pkg.scripts['check:pii']) {
    pkg.scripts['check:pii'] = 'pii-shield-check';
    done.push('package.json に「npm run check:pii」を追加');
  }
  const hasDependency = Boolean(pkg.dependencies?.['pii-shield']);
  writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');

  // 7. PII Shield 本体を依存関係に追加
  if (!hasDependency && install) {
    log(`PII Shield をインストールしています（npm install ${PACKAGE_SOURCE}）…`);
    execSync(`npm install ${PACKAGE_SOURCE} --no-audit --no-fund`, { cwd: root, stdio: 'inherit' });
    done.push('PII Shield をインストール');
  }

  return { done, skipped, configPath, isModule };
}

export function runInit(args) {
  const root = resolve(args.find((a) => !a.startsWith('--')) ?? '.');
  const { done, skipped, configPath, isModule } = init(root, { install: !args.includes('--no-install') });

  console.log(`\n✅ PII Shield のセットアップが完了しました: ${root}\n`);
  for (const d of done) console.log(`  ✔ ${d}`);
  for (const s of skipped) console.log(`  – ${s}`);
  console.log(`
次にやること:
  1. サーバー側のコードで読み込む:  import { shield } from './${configPath}';
  2. 本番サーバー（Vercel など）の環境変数に、.env の PII_KEY_V1 と PII_INDEX_KEY を登録する
     ※ 鍵をなくすと暗号化したデータは二度と読めません。.env の中身は安全な場所にも控えてください
  3. 公開前に「npm run check:pii」で違反がないか確認する
`);
  if (!isModule) console.log('  ※ このアプリは CommonJS 形式のため、設定ファイルは .mjs で作成しました。');
}
