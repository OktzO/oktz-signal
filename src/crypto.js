import { createCipheriv, createDecipheriv, createHmac, createHash, timingSafeEqual } from 'crypto';

// Buffer is a Uint8Array, and callers legitimately hand us a plain one
// (protobuf-decoded bytes, getRandomValues). Normalize rather than reject.
function asBuffer(value) {
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new TypeError(`Expected Buffer or Uint8Array`);
}

export function encrypt(key, data, iv) {
  key = asBuffer(key); data = asBuffer(data); iv = asBuffer(iv);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

export function decrypt(key, data, iv) {
  key = asBuffer(key); data = asBuffer(data); iv = asBuffer(iv);
  const decipher = createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

export function calculateMAC(key, data) {
  key = asBuffer(key); data = asBuffer(data);
  const hmac = createHmac('sha256', key);
  hmac.update(data);
  return Buffer.from(hmac.digest());
}

export function hash(data) {
  data = asBuffer(data);
  return createHash('sha512').update(data).digest();
}

export function deriveSecrets(input, salt, info, chunks = 3) {
  input = asBuffer(input); salt = asBuffer(salt); info = asBuffer(info);
  // Only three expand blocks are derived below; asking for more used to return
  // three silently, handing the caller short key material.
  if (!Number.isInteger(chunks) || chunks < 1 || chunks > 3) {
    throw new Error(`Unsupported HKDF chunk count: ${chunks}`);
  }
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

export function verifyMAC(data, key, mac, length = 32) {
  mac = asBuffer(mac);
  if (mac.length !== length) throw new Error('Bad MAC length');
  const calculated = calculateMAC(key, data).subarray(0, length);
  // Constant-time compare — `equals` leaks byte-prefix timing.
  if (!timingSafeEqual(mac, calculated)) throw new Error('Bad MAC');
}
