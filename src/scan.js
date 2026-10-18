// プロジェクトのファイルを調べて「必ず守ってほしいこと」の違反を見つける（公開・デプロイ前のチェック用）
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { extname, join, relative, sep } from 'node:path';

const SKIP_DIRS = new Set(['node_modules', '.git']);
const MAX_BYTES = 2 * 1024 * 1024;
// 32バイト鍵の base64 表現（44文字）
const KEY_LITERAL = /(PII_KEY\w*|PII_INDEX_KEY|indexKey|keys\s*:\s*\{\s*\d+)\s*[:=]\s*['"`]?([A-Za-z0-9+/]{43}=)/;
const IMPORTS_SHIELD = /(from\s+|require\(\s*|import\(\s*)['"`][^'"`]*pii-shield[^'"`]*['"`]/;
const CLIENT_DIRS = new Set(['public', 'static', 'www', 'client', 'frontend', 'ios', 'android', 'web-build', 'assets']);
const CLIENT_EXTS = new Set(['.html', '.htm', '.vue', '.svelte', '.swift', '.kt', '.dart', '.m', '.java']);
const DB_SECRET = /(DATABASE_URL|DB_PASSWORD|DB_PASS|MONGO(DB)?_UR[IL]|POSTGRES_URL|MYSQL_URL|(postgres(ql)?|mysql|mongodb(\+srv)?):\/\/)/i;
const DB_LIKE_PATH = /(\.sql$|\.sqlite3?$|\.db$|(^|[/\\])(migrations?|seeds?|dumps?|backups?)([/\\]|$))/i;
const IGNORE_MARK = 'pii-shield-ignore';

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(full);
    else if (entry.isFile()) yield full;
  }
}

function readText(file) {
  if (statSync(file).size > MAX_BYTES) return null;
  const buf = readFileSync(file);
  if (buf.subarray(0, 8000).includes(0)) return null; // バイナリは対象外
  return buf.toString('utf8');
}

const isEnvFile = (rel) => /(^|[/\\])\.env(\.[\w-]+)?$/.test(rel) && !rel.endsWith('.example') && !rel.endsWith('.sample');

function isClientSide(rel, text) {
  const parts = rel.split(sep);
  return (
    parts.slice(0, -1).some((p) => CLIENT_DIRS.has(p)) ||
    CLIENT_EXTS.has(extname(rel)) ||
    /^\s*['"]use client['"]/m.test(text)
  );
}

function isGitIgnored(root, rel) {
  try {
    execFileSync('git', ['check-ignore', '-q', rel], { cwd: root, stdio: 'ignore' });
    return true;
  } catch (err) {
    if (err.status === 1) return false; // git はあるが無視されていない
    // git が使えない場合は .gitignore を簡易的に読む
    const gi = join(root, '.gitignore');
    return existsSync(gi) && readFileSync(gi, 'utf8').split(/\r?\n/).some((l) => /^\/?(\.env\*?|\.env\.\*|\*\.env)$/.test(l.trim()));
  }
}

/**
 * @param {string} root              調べるフォルダ
 * @param {object} [opts]
 * @param {string[]} [opts.knownKeys] 実際の鍵の値（環境変数から渡す）。完全一致で探す
 * @returns {{ findings: Array<{level:'error'|'warning', rule:1|2, file:string, line?:number, message:string}> }}
 */
export function scanProject(root, { knownKeys = [] } = {}) {
  const findings = [];
  const keys = knownKeys.filter((k) => typeof k === 'string' && k.length >= 40);
  const add = (level, rule, file, line, message) => findings.push({ level, rule, file, line, message });

  for (const full of walk(root)) {
    const rel = relative(root, full);
    const text = readText(full);
    if (text === null) continue;
    const env = isEnvFile(rel);
    const dbLike = DB_LIKE_PATH.test(rel);
    const lines = text.split(/\r?\n/);
    let hasKey = false;

    lines.forEach((line, i) => {
      if (line.includes(IGNORE_MARK)) return;
      const literal = KEY_LITERAL.test(line);
      const exact = keys.some((k) => line.includes(k));
      if (!literal && !exact) return;
      hasKey = true;
      if (env) return; // .env に鍵があるのは正しい置き場所（ただし下で .gitignore を確認）
      if (dbLike) {
        add('error', 2, rel, i + 1, '鍵がDB関連のファイル（SQL・マイグレーション・バックアップ等）に入っています。DBと一緒に鍵も盗まれます。');
      } else if (isClientSide(rel, text)) {
        add('error', 1, rel, i + 1, '鍵が画面側・スマホアプリ側のファイルに書かれています。アプリは解析されるため、鍵が攻撃者に見えてしまいます。');
      } else {
        add('error', 1, rel, i + 1, '鍵がソースコードに直接書かれています。環境変数（process.env.PII_KEY_V1 など）から読み込んでください。');
      }
    });

    if (!env && IMPORTS_SHIELD.test(text) && isClientSide(rel, text)) {
      const line = lines.findIndex((l) => IMPORTS_SHIELD.test(l)) + 1;
      if (!lines[line - 1].includes(IGNORE_MARK)) {
        add('error', 1, rel, line, 'PII Shield が画面側・スマホアプリ側のコードから読み込まれています。PII Shield はサーバー側でだけ使ってください。');
      }
    }

    if (env && hasKey) {
      if (!isGitIgnored(root, rel)) {
        add('error', 1, rel, undefined, '鍵の入った .env ファイルが .gitignore に入っていません。GitHub などに公開されると鍵が漏れます。.gitignore に「.env」を追加してください。');
      }
      if (DB_SECRET.test(text)) {
        add('warning', 2, rel, undefined, '同じ .env に暗号鍵とDBの接続情報が入っています。このファイル1つが漏れると両方盗まれます。本番では鍵を鍵管理サービスに置いてください。');
      }
    }
  }
  return { findings };
}
