import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AuditLog, ShieldAccessError, ShieldCryptoError, createShield, generateKey } from '../src/index.js';

const K1 = generateKey();
const K2 = generateKey();
const IDX = generateKey();

const schema = {
  email: { index: 'email', mask: 'email' },
  phone: { index: 'phone', mask: 'phone' },
  name: { mask: 'name' },
  cardNumber: { mask: 'card' },
};

function makeShield(extra = {}) {
  return createShield({ keys: { 1: K1 }, activeKeyVersion: 1, indexKey: IDX, schema, ...extra });
}

const user = { id: 'u1', email: 'Taro@Example.com', phone: '090-1234-5678', name: '山田太郎', cardNumber: '4111111111111111', plan: 'free' };

test('暗号化して保存し、本人なら復号できる', () => {
  const shield = makeShield();
  const stored = shield.protect(user);
  assert.equal(stored.plan, 'free'); // schema 外の項目はそのまま
  for (const f of ['email', 'phone', 'name', 'cardNumber']) {
    assert.match(stored[f], /^pii1\.1\./);
    assert.ok(!JSON.stringify(stored).includes(user[f]), `${f} の平文が保存データに残っている`);
  }
  const plain = shield.reveal(stored, { actor: 'u1' });
  assert.deepEqual(plain, { email: user.email, phone: user.phone, name: user.name, cardNumber: user.cardNumber });
});

test('同じ値でも毎回違う暗号文になる', () => {
  const shield = makeShield();
  assert.notEqual(shield.protect(user).email, shield.protect(user).email);
});

test('暗号文を別ユーザーの行へコピーしても復号できない', () => {
  const shield = makeShield();
  const a = shield.protect(user);
  const b = shield.protect({ ...user, id: 'u2', email: 'other@example.com' });
  const swapped = { ...b, email: a.email };
  assert.throws(() => shield.reveal(swapped, { actor: 'u2' }), ShieldCryptoError);
});

test('暗号文を書き換えると検知される', () => {
  const shield = makeShield();
  const stored = shield.protect(user);
  const parts = stored.email.split('.');
  parts[3] = parts[3].slice(0, -2) + (parts[3].endsWith('AA') ? 'BB' : 'AA');
  assert.throws(() => shield.reveal({ ...stored, email: parts.join('.') }, { actor: 'u1' }), ShieldCryptoError);
});

test('鍵が違えば復号できない（DBだけ盗まれたケース）', () => {
  const stored = makeShield().protect(user);
  const attacker = createShield({ keys: { 1: generateKey() }, activeKeyVersion: 1, indexKey: generateKey(), schema });
  assert.throws(() => attacker.reveal(stored, { actor: 'u1' }), ShieldCryptoError);
});

test('ブラインドインデックスで表記ゆれを吸収して検索できる', () => {
  const shield = makeShield();
  const stored = shield.protect(user);
  const q = shield.indexOf('email', '  taro@example.COM ');
  assert.equal(q.column, 'email_bidx');
  assert.equal(stored[q.column], q.value);
  assert.equal(shield.indexOf('phone', '09012345678').value, stored.phone_bidx);
  assert.notEqual(shield.indexOf('email', 'jiro@example.com').value, stored.email_bidx);
  assert.throws(() => shield.indexOf('name', '山田太郎'));
});

test('toPublic は暗号文を出さずマスク値だけ返す', () => {
  const shield = makeShield();
  const pub = shield.toPublic(shield.protect(user));
  assert.deepEqual(pub, {
    id: 'u1',
    plan: 'free',
    email: 'T***@Example.com',
    phone: '*******5678',
    name: '山***',
    cardNumber: '************1111',
  });
});

test('他人のデータは見られない／管理者は利用目的が必要', () => {
  const shield = makeShield();
  const stored = shield.protect(user);
  assert.throws(() => shield.reveal(stored, { actor: 'u2' }), { code: 'FORBIDDEN' });
  assert.throws(() => shield.reveal(stored, { actor: 'admin1', roles: ['admin'] }), { code: 'FORBIDDEN' });
  assert.equal(shield.reveal(stored, { actor: 'admin1', roles: ['admin'], purpose: '問い合わせ対応 #123', fields: ['email'] }).email, user.email);
});

test('短時間に多数のレコードを開くとロックされ、通知される', () => {
  let t = 0;
  const alerts = [];
  const shield = makeShield({
    policy: () => true,
    guard: { perActor: { maxCalls: 100, maxRecords: 3, windowMs: 60_000 }, lockMs: 10_000, onAlert: (a) => alerts.push(a), now: () => t },
  });
  const records = Array.from({ length: 5 }, (_, i) => shield.protect({ ...user, id: `u${i}` }));
  for (let i = 0; i < 3; i++) shield.reveal(records[i], { actor: 'bot' });
  assert.throws(() => shield.reveal(records[3], { actor: 'bot' }), ShieldAccessError);
  assert.equal(alerts[0].type, 'TOO_MANY_RECORDS');
  // ロック中は正当なレコードも見られない
  assert.throws(() => shield.reveal(records[0], { actor: 'bot' }), { code: 'LOCKED' });
  // 他の利用者には影響しない
  assert.ok(shield.reveal(records[4], { actor: 'u4' }));
  // ロック期間が過ぎれば解除
  t += 10_001;
  assert.ok(shield.reveal(records[0], { actor: 'bot' }));
});

test('おとりレコードに触れると即ロック', () => {
  const alerts = [];
  const shield = makeShield({ policy: () => true, guard: { canaryIds: ['honeypot-1'], onAlert: (a) => alerts.push(a) } });
  const canary = shield.protect({ ...user, id: 'honeypot-1' });
  assert.throws(() => shield.reveal(canary, { actor: 'scraper' }), { code: 'LOCKED' });
  assert.equal(alerts[0].type, 'CANARY_TOUCHED');
});

test('システム全体の上限（分散攻撃対策）', () => {
  const shield = makeShield({ policy: () => true, guard: { global: { maxCalls: 2, windowMs: 60_000 } } });
  const stored = shield.protect(user);
  shield.reveal(stored, { actor: 'a' });
  shield.reveal(stored, { actor: 'b' });
  assert.throws(() => shield.reveal(stored, { actor: 'c' }), { code: 'GLOBAL_RATE_LIMIT' });
});

test('監査ログは平文を含まず、改ざんを検知できる', () => {
  const shield = makeShield();
  const stored = shield.protect(user);
  shield.reveal(stored, { actor: 'u1' });
  assert.throws(() => shield.reveal(stored, { actor: 'u2' }));
  const log = shield.audit.entries;
  assert.equal(log.length, 2);
  assert.deepEqual(log.map((e) => e.result), ['allowed', 'denied']);
  assert.ok(!JSON.stringify(log).includes(user.email));
  assert.deepEqual(shield.audit.verify(), { ok: true });

  const tampered = log.map((e) => ({ ...e }));
  tampered[0].actor = 'someone-else';
  assert.deepEqual(AuditLog.verify(tampered), { ok: false, brokenAt: 0 });
  assert.deepEqual(AuditLog.verify(log.slice(1)), { ok: false, brokenAt: 0 }); // 先頭を削除しても検知
});

test('鍵のローテーション', () => {
  const old = makeShield();
  const stored = old.protect(user);
  const shield = createShield({ keys: { 1: K1, 2: K2 }, activeKeyVersion: 2, indexKey: IDX, schema });
  assert.ok(shield.needsRotation(stored));
  const rotated = shield.rotate(stored);
  assert.match(rotated.email, /^pii1\.2\./);
  assert.ok(!shield.needsRotation(rotated));
  assert.equal(shield.reveal(rotated, { actor: 'u1' }).email, user.email);
  // 旧鍵を外しても新しい暗号文は読める
  const v2only = createShield({ keys: { 2: K2 }, activeKeyVersion: 2, indexKey: IDX, schema });
  assert.equal(v2only.reveal(rotated, { actor: 'u1' }).name, user.name);
});

test('設定ミスを起動時に検出する', () => {
  assert.throws(() => createShield({ keys: { 1: 'short' }, activeKeyVersion: 1, indexKey: IDX, schema }), /32 バイト/);
  assert.throws(() => createShield({ keys: { 1: K1 }, activeKeyVersion: 1, indexKey: K1, schema }), /別の鍵/);
  assert.throws(() => createShield({ keys: { 1: K1 }, activeKeyVersion: 2, indexKey: IDX, schema }), /activeKeyVersion/);
  assert.throws(() => makeShield().protect({ email: 'x@y.z' }), /recordId/);
});

test('パスワードハッシュ', async () => {
  const shield = makeShield();
  const hash = await shield.hashPassword('correct horse battery');
  assert.ok(!hash.includes('correct'));
  assert.equal(await shield.verifyPassword('correct horse battery', hash), true);
  assert.equal(await shield.verifyPassword('wrong password!!', hash), false);
  await assert.rejects(shield.hashPassword('short'));
});
