// 実行: npm run demo
// 記事のような攻撃を再現して、PII Shield がどう守るかを確認するデモ
import { createShield, generateKey } from '../src/index.js';

const line = (title) => console.log(`\n=== ${title} ===`);

// 本番では鍵は環境変数や鍵管理サービスから読み込む（コードやスマホアプリに埋め込まない）
const shield = createShield({
  keys: { 1: process.env.PII_KEY_V1 ?? generateKey() },
  activeKeyVersion: 1,
  indexKey: process.env.PII_INDEX_KEY ?? generateKey(),
  schema: {
    email: { index: 'email', mask: 'email' },
    phone: { mask: 'phone' },
    name: { mask: 'name' },
    address: { mask: 'address' },
  },
  guard: {
    perActor: { maxCalls: 20, maxRecords: 3, windowMs: 60_000 },
    canaryIds: ['user-9999'], // 誰のものでもない「おとり」会員
    onAlert: (a) => console.log('  🚨 アラート通知:', a),
  },
});

// --- 会員登録（保存前に protect を通すだけ） ---
const db = new Map();
const members = [
  { id: 'user-1', name: '山田太郎', email: 'taro@example.com', phone: '090-1111-2222', address: '東京都千代田区丸の内1-1-1' },
  { id: 'user-2', name: '佐藤花子', email: 'hanako@example.com', phone: '080-3333-4444', address: '大阪府大阪市北区梅田2-2-2' },
  { id: 'user-3', name: '鈴木一郎', email: 'ichiro@example.com', phone: '070-5555-6666', address: '愛知県名古屋市中区栄3-3-3' },
  { id: 'user-4', name: '高橋次郎', email: 'jiro@example.com', phone: '090-7777-8888', address: '福岡県福岡市博多区4-4-4' },
  { id: 'user-9999', name: 'おとり', email: 'canary@example.com', phone: '000-0000-0000', address: '架空' },
];
for (const m of members) db.set(m.id, shield.protect(m));

line('1. DBの中身（攻撃者がDBを丸ごと盗んでもこれしか見えない）');
console.log(db.get('user-1'));

line('2. ログイン時のメール検索（平文を保存せずに検索できる）');
const q = shield.indexOf('email', 'TARO@example.com');
const found = [...db.values()].find((r) => r[q.column] === q.value);
console.log('  見つかった会員ID:', found.id);

line('3. 一覧画面・APIの応答（復号せずマスク値だけ返す）');
console.log(shield.toPublic(db.get('user-2')));

line('4. 本人がマイページを開く（本人なので復号OK）');
console.log(shield.reveal(db.get('user-1'), { actor: 'user-1' }));

line('5. 偽装したアプリから他人のIDを指定してAPIを叩く');
try {
  shield.reveal(db.get('user-2'), { actor: 'user-1' });
} catch (e) {
  console.log(`  ❌ 拒否: ${e.message}`);
}

line('6. 乗っ取られた管理者アカウントで全会員を順番に抜き取ろうとする（AIによる自動化を想定）');
for (const id of db.keys()) {
  try {
    shield.reveal(db.get(id), { actor: 'admin-x', roles: ['admin'], purpose: 'export' });
    console.log(`  ⚠ ${id} は取得された`);
  } catch (e) {
    console.log(`  ❌ ${id}: ${e.message}`);
  }
}

line('7. 監査ログ（誰が・いつ・何を見たか。平文は残さない）');
for (const e of shield.audit.entries) {
  console.log(`  #${e.seq} ${e.actor} → ${e.recordId} [${e.result}${e.reason ? `: ${e.reason}` : ''}]`);
}
console.log('  ログ改ざんチェック:', shield.audit.verify());
