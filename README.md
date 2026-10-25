# SecureURL

A PWA for saving URLs you want to remember. Everything stays on your device, encrypted with [Nostr NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md).

## How it works

- On first launch you set a numeric PIN (6+ digits). The app generates a Nostr identity (nsec) and shows it once — save it with your PIN.
- Your URL list is encrypted twice with NIP-44: once with a key derived from the PIN (PBKDF2, 600k iterations, salted with your pubkey) and once to your own nsec. It is stored in ; the nsec itself is stored encrypted by the PIN.
- Unlock with the PIN. The app auto-locks when hidden or idle for 2 minutes, and throttles repeated wrong PINs.
- Paste URLs in (one or many); copy them out individually.
- **Backup** publishes the same doubly-encrypted blob as a replaceable Nostr event (kind 30078, ) to a few public relays, only when you press the button. **Restore** takes your nsec + PIN, fetches the latest event, and decrypts it. Relays see only your pubkey, timing and ciphertext size.

> Anyone with your nsec can overwrite your backup; anyone with nsec **and** PIN can read it. A short PIN is weak against someone who holds the nsec. There is no recovery if you lose either.

## Local dev

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # outputs dist/
```

Deploys automatically to Vercel on every push to `main`.
