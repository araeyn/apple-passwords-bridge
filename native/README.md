# Open Passwords Helper

The macOS app connects the extension to Apple’s native Passwords helper. It does not read Keychain databases or keep a separate password vault.

## Install or update

From the repository root, run:

```sh
./native/install-password-helper.sh
```

This builds **Open Passwords Helper.app**, installs it in `~/Applications`, and registers the native hosts for Chrome and Arc. Open the helper, choose a browser, then select **Check selected browser**. Load the extension from the repository root as described in the [main README](../README.md), and allow its native messaging permission if prompted. The extension connects automatically. macOS may separately ask the selected browser to access saved passkeys the first time one is used.

## Build without installing

From this directory, run:

```sh
./build.sh
```

## Troubleshooting

- If the extension cannot connect, rerun the installer and reload the extension.
- If the browser check fails, choose another signed Chromium browser with Apple’s public-key credential entitlement.
- Passkey requests use a temporary browser profile, including requests initiated automatically when a site loads.

## Remove

Choose **Remove Helper** in the app to unregister the native hosts and remove `~/Applications/Open Passwords Helper.app`. To unregister the hosts but keep the app, run `./unregister-password-helper.sh` from this directory.
