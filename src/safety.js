// 「必ず守ってほしいこと」に違反していないかを、アプリ起動時（createShield の呼び出し時）に確認する
//   ルール1: 鍵をスマホアプリやフロントエンド（画面側）に置かない。サーバー側で使い、鍵は環境変数か鍵管理サービスへ
//   ルール2: 鍵とDBを同じ場所に置かない

export class ShieldSecurityError extends Error {
  constructor(warnings) {
    super(warnings.map((w) => `[ルール${w.rule}] ${w.message}`).join('\n'));
    this.name = 'ShieldSecurityError';
    this.code = 'SECURITY_RULE_VIOLATION';
    this.warnings = warnings;
  }
}

// ブラウザやスマホアプリの中で動いていないか
export function detectClientRuntime(g = globalThis) {
  if (typeof g.window !== 'undefined' && typeof g.document !== 'undefined') return 'ブラウザ（フロントエンド）';
  if (g.navigator?.product === 'ReactNative') return 'スマホアプリ（React Native）';
  return null;
}

const DB_ENV_PATTERN = /^(DATABASE_URL|DB_URL|DB_PASSWORD|DB_PASS|MONGO(DB)?_UR[IL]|POSTGRES_URL|MYSQL_URL|REDIS_URL)$/i;

function toBase64(key) {
  return Buffer.isBuffer(key) ? key.toString('base64') : String(key ?? '').trim();
}

/**
 * @param {object} p
 * @param {Array<{label:string, value:string|Buffer}>} p.keys  渡された鍵
 * @param {'env'|'kms'} [p.keySource]                          鍵の取得元（鍵管理サービスなら 'kms'）
 * @param {object} [p.env]                                     環境変数（テスト用に差し替え可能）
 */
export function checkKeyHandling({ keys, keySource = 'env', env = process.env }) {
  const warnings = [];
  const envEntries = Object.entries(env).filter(([, v]) => typeof v === 'string' && v.length > 0);

  for (const { label, value } of keys) {
    const b64 = toBase64(value);
    const fromEnv = envEntries.filter(([, v]) => v.trim() === b64).map(([name]) => name);

    // ルール1: 環境変数にも鍵管理サービスにも無い鍵 ＝ コードや設定ファイルに直接書かれている可能性
    if (fromEnv.length === 0 && keySource !== 'kms') {
      warnings.push({
        rule: 1,
        code: 'KEY_NOT_FROM_ENV',
        message: `${label} が環境変数から読み込まれていません。鍵がソースコードに直接書かれていると、アプリの解析やコードの流出で鍵も盗まれます。`,
        hint: "鍵は process.env.PII_KEY_V1 のように環境変数から読み込んでください。鍵管理サービス（AWS KMS など）から取得している場合は createShield に keySource: 'kms' を指定すると、この警告は出なくなります。",
      });
    }

    // ルール1: フロントエンド向けの公開用環境変数に入っている（ビルド時に画面側のコードへ埋め込まれる）
    const publicVars = fromEnv.filter((name) => /^(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|PUBLIC_)/.test(name));
    if (publicVars.length > 0) {
      warnings.push({
        rule: 1,
        code: 'KEY_IN_PUBLIC_ENV',
        message: `${label} が画面側に公開される環境変数（${publicVars.join(', ')}）に入っています。この名前の変数はビルド時にフロントエンドのコードへ埋め込まれ、誰でも見られます。`,
        hint: 'NEXT_PUBLIC_ / VITE_ / REACT_APP_ / EXPO_PUBLIC_ などの付かない名前（例: PII_KEY_V1）に変えてください。',
      });
    }
  }

  // ルール2: 鍵とDBの接続情報が同じ環境変数の集まりにある（.env が1つ漏れれば両方取られる）
  const dbVars = envEntries.filter(([name]) => DB_ENV_PATTERN.test(name)).map(([name]) => name);
  const keyInEnv = keys.some(({ value }) => envEntries.some(([, v]) => v.trim() === toBase64(value)));
  if (keySource !== 'kms' && keyInEnv && dbVars.length > 0 && env.NODE_ENV === 'production') {
    warnings.push({
      rule: 2,
      code: 'KEY_NEXT_TO_DB',
      message: `本番環境で、暗号鍵とDBの接続情報（${dbVars.join(', ')}）が同じ環境変数に並んでいます。サーバーの設定が1か所漏れるだけで、鍵とDBの両方が盗まれます。`,
      hint: "本番では鍵を鍵管理サービス（AWS KMS / Google Secret Manager など）に移し、keySource: 'kms' を指定してください。",
    });
  }

  return warnings;
}

export function defaultWarningHandler(warning) {
  console.warn(`\n⚠️  [PII Shield 警告｜必ず守ってほしいこと ルール${warning.rule}] ${warning.message}\n   👉 対処法: ${warning.hint}\n`);
}
