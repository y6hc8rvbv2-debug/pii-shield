#!/usr/bin/env node
// まとめ役のコマンド: npx github:y6hc8rvbv2-debug/pii-shield <init|check|keygen>
const [command = 'help', ...args] = process.argv.slice(2);

switch (command) {
  case 'init': {
    const { runInit } = await import('./init.js');
    runInit(args);
    break;
  }
  case 'check':
    process.argv = [process.argv[0], process.argv[1], ...args];
    await import('./check.js');
    break;
  case 'keygen':
    await import('./keygen.js');
    break;
  default:
    console.log(`PII Shield コマンド
  init    新しいアプリに PII Shield を組み込む（設定ファイル・鍵・自動チェック・Claude 用ルールを作成）
  check   「必ず守ってほしいこと」の違反がないか調べる
  keygen  新しい鍵を作る`);
}
