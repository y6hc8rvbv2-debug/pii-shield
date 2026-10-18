// PII Shield: 既存アプリに組み込んで個人情報を守るためのエントリーポイント
import { randomBytes } from 'node:crypto';
import { AuditLog } from './audit.js';
import { blindIndex, decodeKey, decryptValue, encryptValue, isEncrypted, tokenVersion } from './crypto.js';
import { AccessGuard, ShieldAccessError } from './guard.js';
import { applyMask } from './mask.js';
import { hashPassword, verifyPassword } from './password.js';

export { AuditLog, AccessGuard, ShieldAccessError, hashPassword, verifyPassword };
export { ShieldCryptoError } from './crypto.js';
export { maskers } from './mask.js';

const normalizers = {
  email: (v) => String(v).trim().toLowerCase(),
  phone: (v) => String(v).replace(/\D/g, ''),
  default: (v) => String(v).trim().normalize('NFKC'),
};

// 新しい鍵を作る（初回セットアップ・鍵の入れ替え時に使う）
export function generateKey() {
  return randomBytes(32).toString('base64');
}

// 既定の権限ルール: 本人のデータだけ見られる。管理者は purpose（利用目的）の記入が必須。
function defaultPolicy({ actor, ownerId, roles = [], purpose }) {
  if (actor === ownerId) return true;
  return roles.includes('admin') && Boolean(purpose);
}

/**
 * @param {object} options
 * @param {Record<number,string>} options.keys          鍵バージョン → base64 鍵（古い鍵も復号のため残す）
 * @param {number} options.activeKeyVersion              新しく暗号化するときに使う鍵のバージョン
 * @param {string} options.indexKey                      検索用ハッシュの鍵（暗号鍵とは別にする）
 * @param {Record<string,{index?:boolean|'email'|'phone', mask?:string|Function}>} options.schema 守る項目
 * @param {Function} [options.policy]                    誰がどのデータを見てよいかの判定関数
 * @param {object} [options.guard]                       AccessGuard の設定
 * @param {object} [options.audit]                       AuditLog の設定
 */
export function createShield(options) {
  const { schema, activeKeyVersion, policy = defaultPolicy } = options;
  if (!schema || Object.keys(schema).length === 0) throw new Error('schema に守りたい項目を指定してください');

  const keys = new Map(Object.entries(options.keys ?? {}).map(([v, k]) => [Number(v), decodeKey(k, `keys[${v}]`)]));
  const activeKey = keys.get(activeKeyVersion);
  if (!activeKey) throw new Error(`activeKeyVersion ${activeKeyVersion} の鍵が keys にありません`);
  const indexKey = decodeKey(options.indexKey, 'indexKey');
  if ([...keys.values()].some((k) => k.equals(indexKey))) {
    throw new Error('indexKey は暗号鍵と別の鍵にしてください');
  }

  const guard = options.guard instanceof AccessGuard ? options.guard : new AccessGuard(options.guard);
  const audit = options.audit instanceof AuditLog ? options.audit : new AuditLog(options.audit);

  const fieldNames = Object.keys(schema);
  const idxCol = (f) => `${f}_bidx`;
  const maskCol = (f) => `${f}_masked`;

  function normalizer(field) {
    const kind = schema[field].index;
    return normalizers[kind] ?? normalizers[field] ?? normalizers.default;
  }

  function resolveRecordId(record, recordId) {
    const id = recordId ?? record?.id;
    if (id === undefined || id === null || id === '') {
      throw new Error('recordId（または record.id）が必要です。暗号文を各レコードに結び付けるために使います');
    }
    return String(id);
  }

  /** 保存前に呼ぶ: 個人情報を暗号化し、検索用ハッシュと表示用マスクを付けた「DBに入れてよい形」を返す */
  function protect(record, { recordId } = {}) {
    const id = resolveRecordId(record, recordId);
    const out = { ...record };
    for (const field of fieldNames) {
      const value = record[field];
      if (value === undefined || value === null || isEncrypted(value)) continue;
      const rule = schema[field];
      out[field] = encryptValue(activeKey, activeKeyVersion, id, field, value);
      if (rule.index) out[idxCol(field)] = blindIndex(indexKey, field, normalizer(field)(value));
      if (rule.mask) out[maskCol(field)] = applyMask(rule.mask, value);
    }
    return out;
  }

  /** 検索用: 例 db.find({ email_bidx: shield.indexOf('email', 'a@b.com') }) */
  function indexOf(field, value) {
    if (!schema[field]?.index) throw new Error(`項目 "${field}" は index: true になっていません`);
    return { column: idxCol(field), value: blindIndex(indexKey, field, normalizer(field)(value)) };
  }

  /** API応答・一覧画面用: 暗号文と検索用ハッシュを取り除き、マスク済みの値だけを返す（復号しない） */
  function toPublic(stored) {
    const out = { ...stored };
    for (const field of fieldNames) {
      delete out[field];
      delete out[idxCol(field)];
      if (out[maskCol(field)] !== undefined) {
        out[field] = out[maskCol(field)];
        delete out[maskCol(field)];
      }
    }
    return out;
  }

  /**
   * 本当に平文が必要なときだけ呼ぶ: 権限確認 → 異常検知 → 復号 → 監査ログ
   * @param {object} ctx { actor, ownerId?, roles?, purpose?, fields? }
   */
  function reveal(stored, ctx = {}) {
    const recordId = resolveRecordId(stored, ctx.recordId);
    const fields = ctx.fields ?? fieldNames;
    const entry = { action: 'reveal', actor: ctx.actor, recordId, fields, purpose: ctx.purpose };
    const ownerId = String(ctx.ownerId ?? stored.ownerId ?? recordId);

    try {
      guard.check(ctx.actor, recordId);
      if (!policy({ ...ctx, ownerId, recordId })) {
        throw new ShieldAccessError('FORBIDDEN', 'このデータを閲覧する権限がありません');
      }
      const out = {};
      for (const field of fields) {
        if (!schema[field]) throw new Error(`項目 "${field}" は schema にありません`);
        if (stored[field] === undefined || stored[field] === null) continue;
        out[field] = decryptValue(keys, recordId, field, stored[field]);
      }
      audit.append({ ...entry, result: 'allowed' });
      return out;
    } catch (err) {
      audit.append({ ...entry, result: 'denied', reason: err.code ?? err.message });
      throw err;
    }
  }

  /** 古い鍵で暗号化された項目があるか */
  function needsRotation(stored) {
    return fieldNames.some((f) => isEncrypted(stored[f]) && tokenVersion(stored[f]) !== activeKeyVersion);
  }

  /** 鍵の入れ替え: 古い鍵の暗号文を新しい鍵で暗号化し直す（バッチ処理用。監視・権限チェックは通さない） */
  function rotate(stored, { recordId } = {}) {
    const id = resolveRecordId(stored, recordId);
    const out = { ...stored };
    for (const field of fieldNames) {
      if (!isEncrypted(stored[field]) || tokenVersion(stored[field]) === activeKeyVersion) continue;
      const value = decryptValue(keys, id, field, stored[field]);
      out[field] = encryptValue(activeKey, activeKeyVersion, id, field, value);
    }
    audit.append({ action: 'rotate', actor: 'system', recordId: id, fields: fieldNames, result: 'allowed' });
    return out;
  }

  return { protect, reveal, toPublic, indexOf, needsRotation, rotate, guard, audit, hashPassword, verifyPassword };
}
