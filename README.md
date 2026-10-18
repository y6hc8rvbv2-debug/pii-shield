# PII Shield — アプリに組み込める個人情報保護モジュール

「公式アプリを解析 → APIを偽装 → 会員情報を大量に抜き取る」という、AIを使ったとみられる攻撃（日経新聞の記事）への対策を、
**既存のNode.jsアプリに数行で追加できる**ようにしたモジュールです。外部ライブラリは使っていません（Node.js 18以上の標準機能のみ）。

## 何から守るのか（記事の攻撃 → 対策）

| 攻撃の手口 | PII Shield の対策 |
|---|---|
| サーバーやDBに侵入して会員情報を丸ごと持ち出す | **項目ごとの暗号化**（AES-256-GCM）。鍵がなければ盗んだDBは読めない |
| 盗んだメールアドレスの一覧と照合して、DBにある人を割り出す | **鍵付きハッシュ（ブラインドインデックス）**で検索するため、平文のメールアドレスをDBに保存しない |
| 暗号文を別の会員の行にコピーするなどの改ざん | 暗号文を「会員ID＋項目名」に結び付けているので、コピーすると復号に失敗する |
| アプリを偽装して他人のIDでAPIを呼ぶ | **権限ルール**: 既定では本人のデータしか復号できない |
| AIが反応を見ながら大量・高速に試行する（40分で1200回以上） | **アクセス監視**: 短時間に多数の会員を開いたらロックして通知。システム全体の上限も設定できる |
| 総当たりで順番に会員情報を抜く | **おとり（カナリア）会員**: 誰も見るはずのないデータに触れた時点でロック |
| 侵入後にログを消して痕跡を隠す | **改ざん検知つき監査ログ**（ハッシュの鎖） |
| 一覧画面やAPI応答から情報が漏れる | **マスキング**（`t***@example.com` など）。表示用の値は復号せずに出せる |
| パスワードの漏洩 | **scrypt**によるハッシュ化（元に戻せない） |

## 新しいアプリに組み込む（いちばん簡単な方法）

アプリのフォルダで、次のコマンドを1つ実行するだけです。

```bash
npx github:y6hc8rvbv2-debug/pii-shield init
```

これで次のものが自動で用意されます（既にあるファイルは上書きしません）。

| 作られるもの | 役割 |
|---|---|
| `lib/pii-shield.js` | 設定済みの `shield`。サーバー側のコードで `import { shield } from './lib/pii-shield.js'` と読み込むだけで使える |
| `.env` | 新しく作った暗号鍵（`PII_KEY_V1` / `PII_INDEX_KEY`） |
| `.env.example` | 鍵の項目名だけを書いた見本（Git に入れてよい） |
| `.gitignore` | `.env` を Git に入れない設定 |
| `.github/workflows/pii-shield-check.yml` | GitHub に上げるたびに違反がないか自動チェック |
| `CLAUDE.md` | Claude がこのアプリを作業するときに守るルール（個人情報は必ず shield を通す、など） |
| `package.json` | PII Shield 本体と、`npm run check:pii` コマンドを追加 |

> ⚠ セットアップ後、`.env` の2つの鍵を **本番サーバー（Vercel など）の環境変数** にも登録してください。
> 鍵をなくすと暗号化したデータは二度と読めないため、`.env` の中身は安全な場所（パスワード管理アプリなど）にも控えてください。

### Claude にアプリを作ってもらう場合

claude.ai の設定にある「個人設定（Personal preferences）」に次の文を追加しておくと、
Claude が新しいアプリを作るたびに自動で PII Shield を組み込みます。

```
新しいアプリやWebサービスを作るときは、個人情報保護モジュール PII Shield を必ず組み込んでください。
最初にアプリのフォルダで「npx github:y6hc8rvbv2-debug/pii-shield init」を実行し、
作成された CLAUDE.md の「個人情報の扱い」のルールに従ってコードを書いてください。
```

## 使い方（手動で組み込む場合）

### 1. 鍵を作る

```bash
cd pii-shield
npm run keygen
# PII_KEY_V1=....
# PII_INDEX_KEY=....
```

この2つの値は**サーバーの環境変数**（または AWS KMS / Google Secret Manager などの鍵管理サービス）に保存します。

> ⚠ **スマホアプリやフロントエンドのコードに鍵を入れてはいけません。**
> 記事のとおり、公式アプリは解析されます。アプリの中にある秘密は攻撃者にも見えると考えてください。
> PII Shield は必ず**サーバー側**で使います。

### 2. 初期化する

```js
import { createShield } from './pii-shield/src/index.js';

const shield = createShield({
  keys: { 1: process.env.PII_KEY_V1 },
  activeKeyVersion: 1,
  indexKey: process.env.PII_INDEX_KEY,
  // 守りたい項目を書く。index: 検索に使う / mask: 表示用の隠し方
  schema: {
    email:   { index: 'email', mask: 'email' },
    phone:   { index: 'phone', mask: 'phone' },
    name:    { mask: 'name' },
    address: { mask: 'address' },
  },
  guard: {
    perActor: { maxCalls: 30, maxRecords: 5, windowMs: 60_000 }, // 1人あたり1分間に5人分まで
    global:   { maxCalls: 1000, windowMs: 60_000 },              // システム全体の上限
    canaryIds: ['user-9999'],                                    // おとり会員のID
    onAlert: (alert) => notifySlack(alert),                     // 異常時の通知先
  },
  audit: { sink: (entry) => appendToLogServer(entry) },          // 監査ログの保存先
});
```

### 3. 既存コードに組み込む（3か所だけ）

```js
// ① 保存するとき: protect を通してからDBに入れる
await db.users.insert(shield.protect({ id: userId, email, phone, name, address }));

// ② メールアドレスで検索するとき: indexOf でハッシュを作って検索
const { column, value } = shield.indexOf('email', inputEmail);
const user = await db.users.findOne({ [column]: value });   // column は "email_bidx"

// ③ 画面やAPIに返すとき
res.json(shield.toPublic(user));                            // 一覧など: マスク値だけ（復号しない）
res.json(shield.reveal(user, { actor: session.userId }));   // 本人のマイページ: 平文が必要なときだけ
```

`reveal` の中では「監視チェック → 権限チェック → 復号 → 監査ログ記録」が自動で行われ、
問題があれば `ShieldAccessError`（`code`: `FORBIDDEN` / `LOCKED` / `GLOBAL_RATE_LIMIT`）が投げられます。

Express で使う場合の例:

```js
import { ShieldAccessError } from './pii-shield/src/index.js';

app.get('/api/users/:id', requireLogin, async (req, res) => {
  const user = await db.users.findById(req.params.id);
  try {
    res.json(shield.reveal(user, { actor: req.session.userId, roles: req.session.roles }));
  } catch (e) {
    if (e instanceof ShieldAccessError) return res.status(e.code === 'FORBIDDEN' ? 403 : 429).json({ error: e.message });
    throw e;
  }
});
```

管理者が他人のデータを見る場合は `roles: ['admin']` と `purpose`（利用目的。例: `'問い合わせ #123 対応'`）が必要です。
この判定は `policy` オプションで自由に差し替えられます。

### 4. 鍵の入れ替え（年1回など定期的に）

```js
const shield = createShield({ keys: { 1: OLD_KEY, 2: NEW_KEY }, activeKeyVersion: 2, /* ... */ });
for (const user of await db.users.all()) {
  if (shield.needsRotation(user)) await db.users.update(shield.rotate(user));
}
// 全件の入れ替えが終わったら keys から 1 を削除
```

## 「必ず守ってほしいこと」の自動チェック

次の2つのルールに違反すると、警告やエラーが出るようになっています。

- **ルール1**: 鍵をスマホアプリやフロントエンド（画面側）のコードに入れない。PII Shield はサーバー側で使い、鍵は環境変数か鍵管理サービスに置く
- **ルール2**: 鍵とDBを同じ場所に置かない

### ① アプリ起動時のチェック（自動）

`createShield` を呼んだときに自動で確認します。設定は不要です。

| 見つける違反 | ルール | 結果 |
|---|---|---|
| ブラウザ・スマホアプリ（React Native）の中で動いている | 1 | **エラーで停止**（鍵が丸見えになるため必ず止める） |
| 鍵が環境変数から読み込まれていない（コードに直書きの疑い） | 1 | 警告 |
| 鍵が `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` / `EXPO_PUBLIC_` など、画面側に公開される環境変数に入っている | 1 | 警告 |
| 本番環境で、鍵とDBの接続情報（`DATABASE_URL` など）が同じ環境変数に並んでいる | 2 | 警告 |

```js
createShield({
  // ...
  keySource: 'kms',              // 鍵管理サービスから取得している場合に指定（警告が出なくなる）
  strictSecurity: true,          // 本番におすすめ: 警告ではなくエラーで起動を止める
  onSecurityWarning: (w) => notifySlack(w), // 警告の送り先を変える（既定は画面への表示）
});
```

### ② 公開前のファイルチェック（コマンド）

プロジェクトのファイルを調べて違反を探します。

```bash
npx pii-shield-check ./my-app          # 違反があると終了コード 1
npx pii-shield-check ./my-app --strict # 「注意」でも終了コード 1
```

| 見つける違反 | ルール |
|---|---|
| 鍵がソースコードに直接書かれている | 1 |
| 画面側・スマホアプリ側のファイル（`frontend/`, `public/`, `ios/`, `android/`, `'use client'`, `.html` / `.vue` など）で PII Shield を読み込んでいる | 1 |
| 鍵の入った `.env` が `.gitignore` に入っていない | 1 |
| 鍵が SQL・マイグレーション・バックアップなど DB 関連のファイルに入っている | 2 |
| 同じ `.env` に鍵と DB の接続情報が入っている（注意） | 2 |

環境変数 `PII_KEY_V1` などをセットした状態で実行すると、**実際の鍵の値**がビルド済みファイルなどに紛れ込んでいないかも探します。
誤検知の行には `// pii-shield-ignore` と書くと対象外になります。

このリポジトリでは `.github/workflows/check.yml` により、GitHub にコードを上げるたびにテストとこのチェックが自動で実行されます。
組み込み先のアプリでも同じ設定をコピーすると、違反したコードが入るのを防げます。

> ⚠ このチェックは「よくある間違い」を見つける補助です。すべての違反を見つけられるわけではありません。

## 試してみる

```bash
npm run demo   # 記事のような攻撃を再現して、防げる様子を表示
npm test       # 自動テスト（29項目）
npm run check  # 「必ず守ってほしいこと」のチェック
node bin/pii-shield.js init ../my-app --no-install  # 別フォルダのアプリにセットアップ（動作確認用）
```

## 用語の補足（初心者向け）

- **暗号化**: 鍵がないと読めない形に変換すること。DBが盗まれても、鍵が別の場所にあれば中身は読めません。
- **AES-256-GCM**: 世界標準の暗号方式。「改ざんされていないか」も同時にチェックできます。
- **ハッシュ**: 元に戻せない変換。同じ入力からは同じ値が出るので「一致するか」だけを確認できます。
- **ブラインドインデックス**: 鍵付きのハッシュ。鍵がないと「このメールアドレスならこの値」という対応表を作れません。
- **レート制限**: 一定時間内の回数に上限を設けること。人間には不可能な速さの操作を止められます。

## 限界（これだけでは防げないこと）

- **鍵とDBの両方が盗まれた場合**は守れません。鍵は必ずDBとは別の場所（鍵管理サービス）に置いてください。
- アクセス監視の状態はメモリ上にあるため、**サーバーを複数台で動かす場合**は Redis などで共有するよう `AccessGuard` を拡張してください。
- ログイン自体の保護（二要素認証、ログイン試行回数の制限）や、API通信の暗号化（HTTPS）は別途必要です。
- アプリ側の秘密（APIキー等）は解析で抜かれる前提で、**サーバー側で必ず本人確認と権限確認を行う**設計にしてください。
