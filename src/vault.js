import { getPublicKey } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';

const STORE_KEY = 'secureurl.vault.v1';
const BACKUP_PREFIX = 'SECUREURL1';
const ITERATIONS = 600_000;

export const MIN_PIN_LENGTH = 6;

const enc = new TextEncoder();

// Derive a Nostr secret key from PIN + salt, then the NIP-44 self-conversation key.
async function deriveKey(pin, saltHex) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: hexToBytes(saltHex), iterations: ITERATIONS },
    base,
    256
  );
  const sk = new Uint8Array(bits);
  const pk = getPublicKey(sk);
  return nip44.getConversationKey(sk, pk);
}

function readStore() {
  try {
    return JSON.parse(localStorage.getItem(STORE_KEY));
  } catch {
    return null;
  }
}

function writeStore(salt, payload) {
  localStorage.setItem(STORE_KEY, JSON.stringify({ salt, payload }));
}

export function hasVault() {
  const s = readStore();
  return !!(s && s.salt && s.payload);
}

function seal(items, key) {
  return nip44.encrypt(JSON.stringify(items), key);
}

function open(payload, key) {
  const items = JSON.parse(nip44.decrypt(payload, key));
  if (!Array.isArray(items)) throw new Error('Bad vault');
  return items;
}

export class Vault {
  constructor(salt, key, items) {
    this.salt = salt;
    this.key = key;
    this.items = items;
  }

  static async create(pin) {
    const salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const key = await deriveKey(pin, salt);
    const v = new Vault(salt, key, []);
    v.save();
    return v;
  }

  // Throws if the PIN is wrong (NIP-44 MAC check fails).
  static async unlock(pin) {
    const s = readStore();
    const key = await deriveKey(pin, s.salt);
    return new Vault(s.salt, key, open(s.payload, key));
  }

  save() {
    writeStore(this.salt, seal(this.items, this.key));
  }

  // One copy/paste-able encrypted message holding the whole vault.
  backup() {
    return `${BACKUP_PREFIX}.${this.salt}.${seal(this.items, this.key)}`;
  }

  static async restore(text, pin) {
    const parts = text.trim().split('.');
    if (parts.length !== 3 || parts[0] !== BACKUP_PREFIX) throw new Error('Not a SecureURL backup');
    const [, salt, payload] = parts;
    const key = await deriveKey(pin, salt);
    const items = open(payload, key); // throws on wrong PIN
    const v = new Vault(salt, key, items);
    v.save();
    return v;
  }
}

export function wipe() {
  localStorage.removeItem(STORE_KEY);
}
