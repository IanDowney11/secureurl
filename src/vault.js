import { getPublicKey, generateSecretKey, finalizeEvent, verifyEvent } from 'nostr-tools/pure';
import { SimplePool } from 'nostr-tools/pool';
import * as nip44 from 'nostr-tools/nip44';
import * as nip19 from 'nostr-tools/nip19';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';

const STORE_KEY = 'secureurl.vault.v2';
const LEGACY_KEY = 'secureurl.vault.v1';
const ITERATIONS = 600_000;
const BACKUP_KIND = 30078; // NIP-78 app-specific replaceable event
const BACKUP_D = 'secureurl';
const RELAY_TIMEOUT = 8000;

export const MIN_PIN_LENGTH = 6;
export const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net'];

const enc = new TextEncoder();

async function pbkdf2(pin, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, base, 256);
  return new Uint8Array(bits);
}

// A second NIP-44 "self" key derived from the PIN, salted with the account pubkey.
// Data is encrypted by this key AND the nsec, so restoring needs both.
async function pinKeyFor(pin, pkHex) {
  const sk = await pbkdf2(pin, hexToBytes(pkHex));
  return nip44.getConversationKey(sk, getPublicKey(sk));
}

const selfKeyFor = (sk) => nip44.getConversationKey(sk, getPublicKey(sk));

function parseNsec(nsec) {
  try {
    const d = nip19.decode(nsec.trim());
    if (d.type === 'nsec') return d.data;
  } catch {}
  throw new Error('Invalid nsec');
}

function readStore() {
  try {
    return JSON.parse(localStorage.getItem(STORE_KEY));
  } catch {
    return null;
  }
}

export function hasVault() {
  return !!readStore() || !!localStorage.getItem(LEGACY_KEY);
}

export function wipe() {
  localStorage.removeItem(STORE_KEY);
}

const withTimeout = (p, ms = RELAY_TIMEOUT) =>
  Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))]);

export class Vault {
  constructor(sk, pinKey, items) {
    this.sk = sk;
    this.pk = getPublicKey(sk);
    this.selfKey = selfKeyFor(sk);
    this.pinKey = pinKey;
    this.items = items;
  }

  get nsec() {
    return nip19.nsecEncode(this.sk);
  }

  static async create(pin, { sk = generateSecretKey(), items = [] } = {}) {
    const pinKey = await pinKeyFor(pin, getPublicKey(sk));
    const v = new Vault(sk, pinKey, items);
    v.save();
    return v;
  }

  // Throws if the PIN is wrong (NIP-44 MAC check fails).
  static async unlock(pin) {
    const s = readStore();
    if (!s) return Vault.migrateLegacy(pin);
    const pinKey = await pinKeyFor(pin, s.pk);
    const sk = hexToBytes(nip44.decrypt(s.encSk, pinKey));
    const v = new Vault(sk, pinKey, []);
    v.items = v.open(s.payload);
    return v;
  }

  // v1 vaults had a PIN-derived key and no nsec; upgrade by generating one.
  static async migrateLegacy(pin) {
    const s = JSON.parse(localStorage.getItem(LEGACY_KEY));
    const sk = await pbkdf2(pin, hexToBytes(s.salt));
    const items = JSON.parse(nip44.decrypt(s.payload, nip44.getConversationKey(sk, getPublicKey(sk))));
    const v = await Vault.create(pin, { items });
    localStorage.removeItem(LEGACY_KEY);
    return v;
  }

  seal() {
    return nip44.encrypt(nip44.encrypt(JSON.stringify(this.items), this.pinKey), this.selfKey);
  }

  open(payload) {
    const items = JSON.parse(nip44.decrypt(nip44.decrypt(payload, this.selfKey), this.pinKey));
    if (!Array.isArray(items)) throw new Error('Bad vault');
    return items;
  }

  save() {
    localStorage.setItem(
      STORE_KEY,
      JSON.stringify({ pk: this.pk, encSk: nip44.encrypt(bytesToHex(this.sk), this.pinKey), payload: this.seal() })
    );
  }

  // Publish the encrypted vault as a replaceable event; returns { ok, total }.
  async backupToNostr(relays = RELAYS) {
    const event = finalizeEvent(
      { kind: BACKUP_KIND, created_at: Math.floor(Date.now() / 1000), tags: [['d', BACKUP_D]], content: this.seal() },
      this.sk
    );
    const pool = new SimplePool();
    const res = await Promise.allSettled(pool.publish(relays, event).map((p) => withTimeout(p)));
    pool.close(relays);
    return { ok: res.filter((r) => r.status === 'fulfilled').length, total: relays.length };
  }

  static async restoreFromNostr(nsec, pin, relays = RELAYS) {
    const sk = parseNsec(nsec);
    const pk = getPublicKey(sk);
    const pool = new SimplePool();
    let events = [];
    try {
      events = await withTimeout(
        pool.querySync(relays, { kinds: [BACKUP_KIND], authors: [pk], '#d': [BACKUP_D] }, { maxWait: RELAY_TIMEOUT }),
        RELAY_TIMEOUT + 2000
      );
    } finally {
      pool.close(relays);
    }
    const latest = events.filter(verifyEvent).sort((a, b) => b.created_at - a.created_at)[0];
    if (!latest) throw new Error('No backup found for this nsec');
    const v = new Vault(sk, await pinKeyFor(pin, pk), []);
    v.items = v.open(latest.content); // throws on wrong PIN
    v.save();
    return v;
  }
}
