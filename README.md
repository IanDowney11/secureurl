# SecureURL

A PWA for saving URLs you want to remember. Everything stays on your device, encrypted with [Nostr NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md).

## How it works

- On first launch you set a numeric PIN (6+ digits). The PIN and a random salt are run through PBKDF2 (600k iterations) to derive a Nostr secret key; your URL list is encrypted to that key's own pubkey with NIP-44 and stored in `localStorage`. Nothing is ever sent to a server or relay.
- Unlock with the PIN. The app auto-locks when hidden or idle for 2 minutes, and throttles repeated wrong PINs.
- Paste URLs in (one or many); copy them out individually.
- **Backup** produces a single encrypted message (`SECUREURL1.<salt>.<ciphertext>`) you can copy/paste anywhere. **Restore** takes that message plus its PIN.

> The PIN is the only secret: a short PIN can be brute-forced offline if someone gets your backup message. Prefer a longer PIN if you share the backup anywhere public. There is no recovery if you forget it.

## Local dev

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # outputs dist/
```

Deploys automatically to Vercel on every push to `main`.
