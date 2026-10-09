import { createHash, timingSafeEqual } from "node:crypto";

export const RESULTS_PER_PAGE = 128n;

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const FIELD_ORDER = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
export const CURVE_ORDER = 0xfffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140n;
export const MAX_PRIVATE_KEY = CURVE_ORDER - 1n;
export const TOTAL_PAGES = totalPagesForResultsPerPage(RESULTS_PER_PAGE);

const BASE_POINT = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest();
}

function hash160(bytes) {
  return createHash("ripemd160").update(sha256(bytes)).digest();
}

function mod(value, modulo = FIELD_ORDER) {
  const result = value % modulo;
  return result >= 0n ? result : result + modulo;
}

function invert(value, modulo = FIELD_ORDER) {
  let low = mod(value, modulo);
  if (low === 0n) {
    throw new RangeError("Cannot invert zero");
  }

  let high = modulo;
  let lowCoefficient = 1n;
  let highCoefficient = 0n;

  while (low > 1n) {
    const quotient = high / low;
    const nextLow = high - low * quotient;
    const nextCoefficient = highCoefficient - lowCoefficient * quotient;

    high = low;
    highCoefficient = lowCoefficient;
    low = nextLow;
    lowCoefficient = nextCoefficient;
  }

  return mod(lowCoefficient, modulo);
}

function addPoints(left, right) {
  if (left === null) return right;
  if (right === null) return left;

  if (left.x === right.x) {
    if (mod(left.y + right.y) === 0n) {
      return null;
    }

    return doublePoint(left);
  }

  const slope = mod((right.y - left.y) * invert(right.x - left.x));
  const x = mod(slope * slope - left.x - right.x);
  const y = mod(slope * (left.x - x) - left.y);

  return { x, y };
}

function doublePoint(point) {
  if (point === null || point.y === 0n) {
    return null;
  }

  const slope = mod(3n * point.x * point.x * invert(2n * point.y));
  const x = mod(slope * slope - 2n * point.x);
  const y = mod(slope * (point.x - x) - point.y);

  return { x, y };
}

function scalarMultiply(scalar) {
  let remaining = mod(scalar, CURVE_ORDER);
  if (remaining === 0n) {
    return null;
  }

  let result = null;
  let addend = BASE_POINT;

  while (remaining > 0n) {
    if (remaining & 1n) {
      result = addPoints(result, addend);
    }

    addend = doublePoint(addend);
    remaining >>= 1n;
  }

  return result;
}

function bytesFromBigInt(value, length) {
  if (value < 0n) {
    throw new RangeError("Cannot encode a negative bigint");
  }

  const hex = value.toString(16).padStart(length * 2, "0");
  if (hex.length > length * 2) {
    throw new RangeError(`Value does not fit in ${length} bytes`);
  }

  return Buffer.from(hex, "hex");
}

function bigIntFromBytes(bytes) {
  if (bytes.length === 0) {
    return 0n;
  }

  return BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
}

function assertPrivateKey(privateKey) {
  if (privateKey < 1n || privateKey > MAX_PRIVATE_KEY) {
    throw new RangeError("Private key is outside the secp256k1 range");
  }
}

function publicKeyBytes(point, compressed) {
  const x = bytesFromBigInt(point.x, 32);
  const y = bytesFromBigInt(point.y, 32);

  if (!compressed) {
    return Buffer.concat([Buffer.from([0x04]), x, y]);
  }

  return Buffer.concat([Buffer.from([point.y % 2n === 0n ? 0x02 : 0x03]), x]);
}

function checksum(payload) {
  return sha256(sha256(payload)).subarray(0, 4);
}

export function base58Encode(bytes) {
  let value = bigIntFromBytes(bytes);
  let encoded = "";

  while (value > 0n) {
    const remainder = value % 58n;
    encoded = BASE58_ALPHABET[Number(remainder)] + encoded;
    value /= 58n;
  }

  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded = "1" + encoded;
  }

  return encoded;
}

export function base58Decode(text) {
  let value = 0n;

  for (const character of text) {
    const digit = BASE58_ALPHABET.indexOf(character);
    if (digit === -1) {
      throw new Error("Invalid Base58 character");
    }

    value = value * 58n + BigInt(digit);
  }

  const hex = value.toString(16);
  const decoded =
    value === 0n ? Buffer.alloc(0) : Buffer.from(hex.length % 2 === 0 ? hex : `0${hex}`, "hex");

  let leadingZeros = 0;
  for (const character of text) {
    if (character !== "1") break;
    leadingZeros += 1;
  }

  return Buffer.concat([Buffer.alloc(leadingZeros), decoded]);
}

export function base58CheckEncode(payload) {
  return base58Encode(Buffer.concat([payload, checksum(payload)]));
}

export function base58CheckDecode(text) {
  const decoded = base58Decode(text);
  if (decoded.length < 5) {
    throw new Error("Base58Check payload is too short");
  }

  const payload = decoded.subarray(0, decoded.length - 4);
  const actualChecksum = decoded.subarray(decoded.length - 4);
  const expectedChecksum = checksum(payload);

  if (!timingSafeEqual(actualChecksum, expectedChecksum)) {
    throw new Error("Invalid Base58Check checksum");
  }

  return payload;
}

export function privateKeyToWif(privateKey, compressed = false) {
  assertPrivateKey(privateKey);

  const payload = compressed
    ? Buffer.concat([Buffer.from([0x80]), bytesFromBigInt(privateKey, 32), Buffer.from([0x01])])
    : Buffer.concat([Buffer.from([0x80]), bytesFromBigInt(privateKey, 32)]);

  return base58CheckEncode(payload);
}

export function decodeWif(wif) {
  const payload = base58CheckDecode(wif);
  if (payload[0] !== 0x80) {
    throw new Error("WIF is not for Bitcoin mainnet");
  }

  const compressed = payload.length === 34 && payload[33] === 0x01;
  if (payload.length !== 33 && !compressed) {
    throw new Error("Invalid WIF payload length");
  }

  const privateKey = bigIntFromBytes(payload.subarray(1, 33));
  assertPrivateKey(privateKey);

  return { privateKey, compressed };
}

export function addressFromPublicKey(publicKey) {
  return base58CheckEncode(Buffer.concat([Buffer.from([0x00]), hash160(publicKey)]));
}

export function privateKeyToAddresses(privateKey) {
  assertPrivateKey(privateKey);

  const point = scalarMultiply(privateKey);
  if (point === null) {
    throw new RangeError("Private key maps to the point at infinity");
  }

  return {
    compressed: addressFromPublicKey(publicKeyBytes(point, true)),
    uncompressed: addressFromPublicKey(publicKeyBytes(point, false)),
  };
}

export function keyRecord(privateKey, point = scalarMultiply(privateKey)) {
  assertPrivateKey(privateKey);
  if (point === null) {
    throw new RangeError("Private key maps to the point at infinity");
  }

  return {
    privateKey: privateKeyToWif(privateKey, false),
    hex: privateKey.toString(16).padStart(64, "0"),
    number: privateKey.toString(),
    compressed: addressFromPublicKey(publicKeyBytes(point, true)),
    uncompressed: addressFromPublicKey(publicKeyBytes(point, false)),
  };
}

export function totalPagesForResultsPerPage(resultsPerPage = RESULTS_PER_PAGE) {
  const perPage = BigInt(resultsPerPage);
  return (MAX_PRIVATE_KEY + perPage - 1n) / perPage;
}

export function totalPagesForPrivateKeyRange(firstPrivateKey, lastPrivateKey, resultsPerPage = RESULTS_PER_PAGE) {
  const first = BigInt(firstPrivateKey);
  const last = BigInt(lastPrivateKey);
  const perPage = BigInt(resultsPerPage);

  if (first < 1n || last > MAX_PRIVATE_KEY || first > last) {
    throw new RangeError("Private key range is outside the secp256k1 range");
  }

  return (last - first + 1n + perPage - 1n) / perPage;
}

export function computePageKeys(page, resultsPerPage = Number(RESULTS_PER_PAGE)) {
  const normalizedPage = BigInt(page);
  const perPage = BigInt(resultsPerPage);
  const firstPrivateKey = (normalizedPage - 1n) * perPage + 1n;

  if (firstPrivateKey > MAX_PRIVATE_KEY) {
    return [];
  }

  const records = [];
  let privateKey = firstPrivateKey;
  let point = scalarMultiply(privateKey);

  for (let index = 0n; index < perPage && privateKey <= MAX_PRIVATE_KEY; index += 1n) {
    records.push(keyRecord(privateKey, point));
    privateKey += 1n;

    if (privateKey <= MAX_PRIVATE_KEY) {
      point = addPoints(point, BASE_POINT);
    }
  }

  return records;
}

export function computePrivateKeyRangePage(page, firstPrivateKey, lastPrivateKey, resultsPerPage = Number(RESULTS_PER_PAGE)) {
  const normalizedPage = BigInt(page);
  if (normalizedPage < 1n) {
    return [];
  }

  const first = BigInt(firstPrivateKey);
  const last = BigInt(lastPrivateKey);
  const perPage = BigInt(resultsPerPage);
  const pageFirstPrivateKey = first + (normalizedPage - 1n) * perPage;

  if (first < 1n || last > MAX_PRIVATE_KEY || first > last) {
    throw new RangeError("Private key range is outside the secp256k1 range");
  }

  if (pageFirstPrivateKey > last) {
    return [];
  }

  const records = [];
  let privateKey = pageFirstPrivateKey;
  let point = scalarMultiply(privateKey);

  for (let index = 0n; index < perPage && privateKey <= last; index += 1n) {
    records.push(keyRecord(privateKey, point));
    privateKey += 1n;

    if (privateKey <= last) {
      point = addPoints(point, BASE_POINT);
    }
  }

  return records;
}
