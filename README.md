# Open Passwords

Use Apple Passwords for website logins and passkeys in Ardia and other Chromium browsers on macOS.

<p align="center">
  <a href="https://github.com/araeyn/apple-passwords-bridge/releases/latest/download/Open-Passwords-Extension.crx"><img alt="Download extension" src="https://img.shields.io/badge/Download-Extension%20(CRX)-1677ff?style=for-the-badge"></a>
  <a href="https://github.com/araeyn/apple-passwords-bridge/releases/latest/download/Open-Passwords-Helper-macOS.zip"><img alt="Download helper app" src="https://img.shields.io/badge/Download-Helper%20for%20macOS-333333?style=for-the-badge"></a>
</p>

## Install

You need macOS 13 or later and Apple Passwords set up.

1. Download and unzip **Open Passwords Helper**. Move the app to **Applications** and open it. Click **Install Helper**, choose your browser, then click **Check selected browser**.
2. Download the **Extension**. Open your browser’s extensions page, turn on **Developer mode**, and drag the `.crx` file onto the page.
3. Pin **Open Passwords** to the browser toolbar. Allow native messaging and website access if asked.

Updating from an older unpacked install? Remove the old extension first, then install the release CRX.

If your browser will not accept the CRX, [download the unpacked extension](https://github.com/araeyn/apple-passwords-bridge/releases/latest/download/Open-Passwords-Extension-Unpacked.zip), unzip it, and choose **Load unpacked** on the extensions page.

## Use

- Choose a saved login from the extension popup or a field suggestion. Submitted new or changed passwords can be saved to Apple Passwords.
- Explicit passkey requests open in the selected browser by default. Turn off **Use helper for passkey requests** to use the current browser’s passkey flow. Conditional suggestions use the browser’s native UI.
- The helper stays connected while idle and reconnects when the browser starts.

Credentials stay on your Mac. The helper does not keep a separate vault; decrypted passwords are held in memory for up to two minutes.

## macOS prompts

The helper is ad hoc signed and is not notarized. If macOS blocks the first launch, Control-click the app in Finder, choose **Open**, then confirm. macOS may also show folder-access or app-management prompts when the helper starts the selected browser; review each prompt before approving it.

To ad hoc sign the app from Terminal:

```sh
APP="$HOME/Applications/Open Passwords Helper.app"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"
```

Ad hoc signing does not notarize the app or remove macOS prompts.

## Remove

Choose **Remove Helper** in the app, then remove **Open Passwords** from your browser. For source builds and release details, see [native/README.md](native/README.md).
