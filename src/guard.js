// アクセス監視: 記事のような「AIによる高速・大量の試行」を検知して止める

export class ShieldAccessError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ShieldAccessError';
    this.code = code;
  }
}

export class AccessGuard {
  constructor({
    perActor = { maxCalls: 30, maxRecords: 5, windowMs: 60_000 },
    global = { maxCalls: 1_000, windowMs: 60_000 },
    lockMs = 15 * 60_000,
    canaryIds = [],
    onAlert = () => {},
    now = () => Date.now(),
  } = {}) {
    this.perActor = perActor;
    this.global = global;
    this.lockMs = lockMs;
    this.canaryIds = new Set(canaryIds.map(String));
    this.onAlert = onAlert;
    this.now = now;
    this.history = new Map(); // actor -> [{ t, recordId }]
    this.globalHits = [];
    this.locks = new Map(); // actor -> 解除時刻
  }

  isLocked(actor) {
    const until = this.locks.get(actor);
    if (until === undefined) return false;
    if (this.now() >= until) {
      // 解除時は履歴もリセットする（残すと解除直後に再ロックされる）
      this.unlock(actor);
      return false;
    }
    return true;
  }

  unlock(actor) {
    this.locks.delete(actor);
    this.history.delete(actor);
  }

  #lock(actor, reason, detail) {
    this.locks.set(actor, this.now() + this.lockMs);
    this.onAlert({ type: reason, actor, at: new Date(this.now()).toISOString(), ...detail });
  }

  // 復号の直前に呼ぶ。問題があれば ShieldAccessError を投げる。
  check(actor, recordId) {
    const now = this.now();
    if (!actor) throw new ShieldAccessError('NO_ACTOR', '誰がアクセスしたか（actor）の指定が必要です');
    if (this.isLocked(actor)) {
      throw new ShieldAccessError('LOCKED', 'このアカウントは不審なアクセスのため一時停止中です');
    }

    // おとり（カナリア）レコード: 正規の利用者が触るはずのないデータ。
    // 触られた時点で「総当たりで抜き取りを試みている」と判断できる。
    if (this.canaryIds.has(String(recordId))) {
      this.#lock(actor, 'CANARY_TOUCHED', { recordId });
      throw new ShieldAccessError('LOCKED', 'このアカウントは不審なアクセスのため一時停止中です');
    }

    // システム全体の上限（多数のアカウントに分散した攻撃への備え）
    this.globalHits = this.globalHits.filter((t) => now - t < this.global.windowMs);
    if (this.globalHits.length >= this.global.maxCalls) {
      this.onAlert({ type: 'GLOBAL_RATE_LIMIT', actor, at: new Date(now).toISOString() });
      throw new ShieldAccessError('GLOBAL_RATE_LIMIT', '現在アクセスが集中しているため個人情報の表示を制限しています');
    }

    // 利用者ごとの上限
    const hits = (this.history.get(actor) ?? []).filter((h) => now - h.t < this.perActor.windowMs);
    hits.push({ t: now, recordId: String(recordId) });
    this.history.set(actor, hits);
    this.globalHits.push(now);

    const distinct = new Set(hits.map((h) => h.recordId)).size;
    if (hits.length > this.perActor.maxCalls) {
      this.#lock(actor, 'TOO_MANY_CALLS', { calls: hits.length, windowMs: this.perActor.windowMs });
      throw new ShieldAccessError('LOCKED', 'アクセスが多すぎるため一時停止しました');
    }
    if (distinct > this.perActor.maxRecords) {
      this.#lock(actor, 'TOO_MANY_RECORDS', { records: distinct, windowMs: this.perActor.windowMs });
      throw new ShieldAccessError('LOCKED', '短時間に多数の利用者情報へアクセスしたため一時停止しました');
    }
  }
}
