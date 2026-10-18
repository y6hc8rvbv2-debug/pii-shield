// 暗号処理（Node.js 標準の node:crypto のみを使用）
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  randomBytes,
} from 'node:crypto';

const PREFIX = 'pii1';
const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;

export class ShieldCryptoError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ShieldCryptoError';
    this.code = 'DECRYPT_FAILED';
  }
}

// base64 文字列または Buffer を 32 バイト鍵として読み込む
export function decodeKey(key, label) {
  const buf = Buffer.isBuffer(key) ? key : Buffer.from(String(key ?? ''), 'base64');
  if (buf.length !== 32) {
    throw new Error(`${label} は 32 バイト（base64 で 44 文字）の鍵が必要です。npm run keygen で生成してください`);
  }
  return buf;
}

// マスター鍵から「レコード×項目」ごとに別の鍵を派生させる。
// 1つの鍵が漏れても他の利用者・他の項目には波及しない。
function deriveFieldKey(masterKey, recordId, field) {
  return Buffer.from(
    hkdfSync('sha256', masterKey, Buffer.from(String(recordId)), Buffer.from(`pii-shield:${field}`), 32),
  );
}

// AAD（追加認証データ）にレコードIDと項目名を入れることで、
// 暗号文を別ユーザーの行や別の列にコピーする改ざんを検知できる。
function aad(recordId, field, version) {
  return Buffer.from(`${recordId}|${field}|v${version}`);
}

export function isEncrypted(value) {
  return typeof value === 'string' && value.startsWith(`${PREFIX}.`);
}

export function tokenVersion(token) {
  if (!isEncrypted(token)) return null;
  return Number(token.split('.')[1]);
}

// 形式: pii1.<鍵バージョン>.<IV>.<暗号文>.<認証タグ>
export function encryptValue(masterKey, version, recordId, field, value) {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, deriveFieldKey(masterKey, recordId, field), iv);
  cipher.setAAD(aad(recordId, field, version));
  // JSON 化して数値や null の型も復元できるようにする
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return [
    PREFIX,
    version,
    iv.toString('base64url'),
    ciphertext.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
  ].join('.');
}

export function decryptValue(keys, recordId, field, token) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 5 || parts[0] !== PREFIX) {
    throw new ShieldCryptoError(`項目 "${field}" は暗号化形式ではありません`);
  }
  const version = Number(parts[1]);
  const masterKey = keys.get(version);
  if (!masterKey) throw new ShieldCryptoError(`鍵バージョン ${version} が見つかりません`);
  try {
    const decipher = createDecipheriv(
      ALGORITHM,
      deriveFieldKey(masterKey, recordId, field),
      Buffer.from(parts[2], 'base64url'),
    );
    decipher.setAAD(aad(recordId, field, version));
    decipher.setAuthTag(Buffer.from(parts[4], 'base64url'));
    const plain = Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64url')), decipher.final()]);
    return JSON.parse(plain.toString('utf8'));
  } catch {
    // 原因（鍵違い・改ざん等）の詳細は攻撃者のヒントになるので返さない
    throw new ShieldCryptoError(`項目 "${field}" の復号に失敗しました（改ざん・鍵不一致の可能性）`);
  }
}

// ブラインドインデックス: 平文を保存せずに「同じ値か」だけを検索できるハッシュ。
// 鍵付き HMAC なので、鍵がなければ辞書攻撃で元のメールアドレスを当てられない。
export function blindIndex(indexKey, field, normalizedValue) {
  return createHmac('sha256', indexKey).update(`${field}\u0000${normalizedValue}`).digest('hex');
}
