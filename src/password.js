// パスワードは「復号できない」ハッシュで保存する（scrypt: 総当たりに強い計算の重いハッシュ）
import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

const PARAMS = { N: 16384, r: 8, p: 1 };
const KEY_LEN = 64;

function scryptAsync(password, salt, params) {
  return new Promise((resolve, reject) => {
    scrypt(password.normalize('NFKC'), salt, KEY_LEN, { ...params, maxmem: 64 * 1024 * 1024 }, (err, key) =>
      err ? reject(err) : resolve(key),
    );
  });
}

export async function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8) {
    throw new Error('パスワードは8文字以上の文字列にしてください');
  }
  const salt = randomBytes(16);
  const key = await scryptAsync(password, salt, PARAMS);
  return ['scrypt', PARAMS.N, PARAMS.r, PARAMS.p, salt.toString('base64url'), key.toString('base64url')].join('$');
}

export async function verifyPassword(password, stored) {
  const [alg, N, r, p, salt, hash] = String(stored).split('$');
  if (alg !== 'scrypt' || typeof password !== 'string') return false;
  const expected = Buffer.from(hash, 'base64url');
  const actual = await scryptAsync(password, Buffer.from(salt, 'base64url'), { N: +N, r: +r, p: +p });
  // 比較時間から正解を推測されないよう、一定時間で比較する
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
