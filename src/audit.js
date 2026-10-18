// 改ざん検知つき監査ログ
// 各ログに「1つ前のログのハッシュ」を含めて鎖のようにつなぐ。
// 攻撃者が痕跡を消そうと途中のログを書き換えると、以降の鎖が合わなくなる。
import { createHash } from 'node:crypto';

const GENESIS = '0'.repeat(64);

function hashEntry(prevHash, body) {
  return createHash('sha256').update(prevHash).update(JSON.stringify(body)).digest('hex');
}

function bodyOf(entry) {
  // キーの順番を固定してハッシュが安定するようにする
  return {
    seq: entry.seq,
    at: entry.at,
    action: entry.action,
    actor: entry.actor ?? null,
    recordId: entry.recordId ?? null,
    fields: entry.fields ?? [],
    purpose: entry.purpose ?? null,
    result: entry.result,
    reason: entry.reason ?? null,
  };
}

export class AuditLog {
  constructor({ sink, now = () => Date.now() } = {}) {
    this.sink = sink; // 外部保存先（ファイル・ログ基盤など）。DBとは別の場所が望ましい
    this.now = now;
    this.entries = [];
    this.lastHash = GENESIS;
  }

  // ※ 平文の個人情報は絶対にログへ書かない（項目名だけを書く）
  append(event) {
    const body = bodyOf({ ...event, seq: this.entries.length + 1, at: new Date(this.now()).toISOString() });
    const entry = { ...body, prevHash: this.lastHash, hash: hashEntry(this.lastHash, body) };
    this.entries.push(entry);
    this.lastHash = entry.hash;
    this.sink?.(entry);
    return entry;
  }

  static verify(entries) {
    let prev = GENESIS;
    for (const [i, entry] of entries.entries()) {
      if (entry.prevHash !== prev || entry.hash !== hashEntry(prev, bodyOf(entry))) {
        return { ok: false, brokenAt: i };
      }
      prev = entry.hash;
    }
    return { ok: true };
  }

  verify() {
    return AuditLog.verify(this.entries);
  }
}
