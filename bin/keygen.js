#!/usr/bin/env node
// 鍵を生成して .env 形式で表示する。表示された値はソースコードやアプリ本体に埋め込まず、
// サーバーの環境変数やクラウドの鍵管理サービス（AWS KMS / GCP Secret Manager 等）に保存すること。
import { generateKey } from '../src/index.js';

console.log(`PII_KEY_V1=${generateKey()}`);
console.log(`PII_INDEX_KEY=${generateKey()}`);
