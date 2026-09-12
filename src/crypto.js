import { createCipheriv, createDecipheriv, createHmac, createHash, timingSafeEqual } from 'crypto';

function assertBuffer(value) {
  if (!(value instanceof Buffer)) throw new TypeError(`Expected Buffer`);
  return value;
}

export function encrypt(key, data, iv) {
  assertBuffer(key); assertBuffer(data); assertBuffer(iv);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

export function decrypt(key, data, iv) {
  assertBuffer(key); assertBuffer(data); assertBuffer(iv);
  const decipher = createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

export function calculateMAC(key, data) {
  assertBuffer(key); assertBuffer(data);
  const hmac = createHmac('sha256', key);
  hmac.update(data);
  return Buffer.from(hmac.digest());
}

export function hash(data) {
  assertBuffer(data);
  return createHash('sha512').update(data).digest();
}

export function deriveSecrets(input, salt, info, chunks = 3) {
  assertBuffer(input); assertBuffer(salt); assertBuffer(info);
  if (salt.byteLength !== 32) throw new Error('Incorrect salt length');
  const PRK = calculateMAC(salt, input);
  const infoArray = new Uint8Array(info.byteLength + 1 + 32);
  infoArray.set(info, 32);
  infoArray[infoArray.length - 1] = 1;
  const signed = [calculateMAC(PRK, Buffer.from(infoArray.slice(32)))];
  if (chunks > 1) {
    infoArray.set(signed[signed.length - 1], 0);
    infoArray[infoArray.length - 1] = 2;
    signed.push(calculateMAC(PRK, Buffer.from(infoArray)));
  }
  if (chunks > 2) {
    infoArray.set(signed[signed.length - 1], 0);
    infoArray[infoArray.length - 1] = 3;
    signed.push(calculateMAC(PRK, Buffer.from(infoArray)));
  }
  return signed;
}

export function verifyMAC(data, key, mac, length) {
  assertBuffer(mac);
  if (mac.length !== length) throw new Error('Bad MAC length');
  const calculated = calculateMAC(key, data).subarray(0, length);
  // Constant-time compare — `equals` leaks byte-prefix timing.
  if (!timingSafeEqual(mac, calculated)) throw new Error('Bad MAC');
}
