// 画面表示・API応答用のマスキング（一部だけ見せて残りを隠す）

const STAR = '*';

function maskMiddle(str, keepStart, keepEnd) {
  const chars = [...str];
  if (chars.length <= keepStart + keepEnd) return STAR.repeat(Math.max(chars.length, 3));
  return chars.slice(0, keepStart).join('') + STAR.repeat(chars.length - keepStart - keepEnd) + chars.slice(chars.length - keepEnd).join('');
}

export const maskers = {
  // taro.yamada@example.com → t*********@example.com
  email(value) {
    const [local, domain] = String(value).split('@');
    if (!domain) return maskMiddle(String(value), 1, 0);
    return `${maskMiddle(local, 1, 0)}@${domain}`;
  },
  // 090-1234-5678 → *********5678（下4桁のみ）
  phone(value) {
    const digits = String(value).replace(/\D/g, '');
    return maskMiddle(digits, 0, 4);
  },
  // 山田太郎 → 山***
  name(value) {
    return maskMiddle(String(value), 1, 0);
  },
  // 4111111111111111 → ************1111
  card(value) {
    const digits = String(value).replace(/\D/g, '');
    return maskMiddle(digits, 0, 4);
  },
  // 東京都千代田区丸の内1-1-1 → 東京都*******（先頭3文字のみ）
  address(value) {
    return maskMiddle(String(value), 3, 0);
  },
  // 何も見せない
  full() {
    return '********';
  },
};

export function applyMask(kind, value) {
  if (value === null || value === undefined) return value;
  if (typeof kind === 'function') return kind(value);
  const masker = maskers[kind];
  if (!masker) throw new Error(`未知のマスク種別です: ${kind}`);
  return masker(value);
}
