# Open Passwords

Use Apple Passwords for website logins and passkeys in Chrome or Arc on macOS. The extension connects to Apple’s native Passwords service through the Open Passwords Helper app.

Passkey support is experimental and may not work on every site.

## Requirements

- macOS 13 or later, with Apple Passwords set up.
- Chrome or Arc.
- A signed Chromium browser with Apple’s public-key credential entitlement, selected in the helper.

## Install

1. From this folder, run `./native/install-password-helper.sh`.
2. Open **Open Passwords Helper** from `~/Applications`. Choose a browser and select **Check selected browser**.
3. In Chrome or Arc, open the extensions page, turn on Developer mode, select **Load unpacked**, and choose this repository’s root folder—the folder containing `manifest.json`.
4. Allow the extension's native messaging permission if the browser asks during installation or reload. The extension connects automatically; there is no Connect button. Allow website access when asked so autofill can work.

macOS may separately ask once before allowing access to saved passkeys. Choose **Allow** to use Apple Passwords passkeys.

## Use

- Choose an account from the extension popup or a field suggestion to fill a login.
- New or changed passwords can be saved to Apple Passwords after form submission.
- Explicit passkey sign-in and registration use the helper by default. Conditional passkey suggestions stay in the browser showing the site. Change this in the extension settings.

## Privacy

The extension needs access to supported websites to detect login fields and autofill. Its native messaging permission lets it connect to the installed helper automatically. macOS separately controls whether passkeys are available to the browser. Passwords are handled locally through Apple’s helper; this app does not read Keychain databases or maintain a password vault. Decrypted passwords are cached in memory for up to two minutes. The extension does not request browser history, Downloads, desktop, documents, or file access.

## Troubleshooting and removal

- If the extension cannot connect, run `./native/install-password-helper.sh` again, then reload the extension.
- After reloading the extension, refresh any open website tabs before retrying passkeys.
- If the browser check fails, choose another browser with Apple’s public-key credential entitlement.
- To remove the helper and its browser registrations, use **Remove Helper** in the app. Remove the extension from the browser’s extensions page.

For helper build details and additional troubleshooting, see [native/README.md](native/README.md).
