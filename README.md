# SecureURL

A PWA for saving URLs you want to remember. Everything stays on your device, encrypted with [Nostr NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md).

## How it works

- On first launch you set a numeric PIN (9+ digits). The app generates a Nostr identity (nsec) and shows it once — save it with your PIN.
- Your URL list is encrypted twice with NIP-44: once with a key derived from the PIN (scrypt, 128 MB memory-hard, salted with your pubkey) and once to your own nsec. It is stored in `localStorage`; the nsec itself is stored encrypted by the PIN.
- Unlock with the PIN. The app auto-locks when hidden or idle for 30 seconds, throttles repeated wrong PINs, and erases the local copy after 10 wrong attempts (restore from Nostr).
- Paste URLs in (one or many); the clipboard is cleared right after pasting. URLs cannot be copied out: long-press a link to open it in a private tab.
- **Backup** publishes the same doubly-encrypted blob as a replaceable Nostr event (kind 30078, `d=secureurl`) to a few public relays, only when you press the button. **Restore** takes your nsec + PIN, fetches the latest event, and decrypts it. Relays see only your pubkey, timing and ciphertext size.

> Anyone with your nsec can overwrite your backup; anyone with nsec **and** PIN can read it. A short PIN is weak against someone who holds the nsec. There is no recovery if you lose either.

## Local dev

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # outputs dist/
```

Deploys automatically to Vercel on every push to `main`.
