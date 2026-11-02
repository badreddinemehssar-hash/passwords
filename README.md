# Badr Vault (personal offline password vault prototype)

A mobile-first encrypted password manager. It uses Web Crypto (PBKDF2-SHA256, 600,000 iterations, AES-256-GCM), random per-save nonce, IndexedDB, and a local-first service worker. All personal account details are inside one encrypted vault record. No accounts, external libraries, trackers or remote APIs.

**This is an independent, unaudited prototype, not a substitute for Apple Passwords, 1Password, or Bitwarden for important credentials.** Browser storage can be erased or evicted; **export encrypted backups regularly** and keep the master password somewhere you will not lose. Web apps do not have native iPhone Password AutoFill, Face ID protection, or iCloud Keychain synchronization. Clipboard content may remain in the iPhone pasteboard after copying.

## Publish and install on an iPhone

1. Create a GitHub repository (public is fine **for these app source files only**, not real account data or backup exports). Upload the **contents** of this folder to the repository root, including `index.html`, `app.js`, `app.css`, `sw.js`, `manifest.webmanifest`, and the PNG icons. **Never upload password backups or credentials.**
2. Repository **Settings → Pages → Deploy from a branch → main → /(root) → Save**. Wait for GitHub to display an `https://<account>.github.io/<repository>/` address.
3. On the iPhone, open that address in **Safari**. Choose Share → Add to Home Screen → **Open as Web App** → Add.
4. Launch from the new Home Screen icon. **Create your vault there**, rather than on the Safari tab, since Home Screen apps can have separate browser storage.
5. Set a long, unique master password (12 characters minimum; a memorable 5+ word passphrase is stronger). Add accounts. Tap **Settings → Export encrypted backup** and store the `.json` file somewhere safe outside this app. The encrypted backup can be restored on another device using its original master password.

The app needs HTTPS (e.g. GitHub Pages) or localhost for the Web Crypto API. Opening the HTML file directly in iOS Files does not provide a reliable secure installed app. Online access is needed for the *first* load, then the service worker caches all app files so it can operate offline. Your vault itself resides on the phone, not on GitHub.

## Notes and limitations

- The master password is **not saved** anywhere; it cannot be reset if forgotten. Backups cannot be unlocked without the original password.
- Replacing a vault by importing a backup deletes the old local vault. Confirm backup provenance before import.
- Deleting the app, changing its URL, Safari data cleanup, or storage eviction may remove saved content. **Do not rely solely on on-device browser storage.**
- Changing the master password creates a new encryption salt and key; **make a new backup** afterward.
- A service worker serves the app shell offline. Files served by the hosting provider can change if you update your repository. Protect your GitHub account.
- As with other password managers, an unlocked app or a compromised phone can expose passwords. This app also lacks a professional independent security audit.

## Local test on a computer

Run `python3 -m http.server 8000` in this folder and visit `http://localhost:8000` (localhost is treated as a secure context). For production, only use HTTPS.
