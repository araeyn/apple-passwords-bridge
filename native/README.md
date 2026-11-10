# Helper and releases

For regular installation, use the downloads and steps in the [main README](../README.md).

## Build from source

From the repository root, run:

```sh
./native/install-password-helper.sh
```

This builds a universal macOS app, ad hoc signs it, installs it in `~/Applications`, and registers the native messaging hosts. The app supports macOS 13 and later.

To build without installing, run `./native/build.sh`. The app is not notarized; macOS may ask you to approve its first launch.

## Publish a release

Update the matching versions in `manifest.json` and `native/Info.plist`, then push a version tag such as `v1.0.0`. GitHub Actions builds the helper app, CRX, unpacked extension ZIP, and checksums, then attaches them to a stable GitHub Release.

The CRX signing key is stored as the GitHub Actions secret `CRX_PRIVATE_KEY`. Keep the private PEM out of the repository. The public key in `manifest.json` determines the extension ID and must continue to match the private key.

## Troubleshooting

- If the extension cannot reach the helper, open the helper app and click **Install Helper**, then reload the extension and refresh the page.
- If browser compatibility fails, choose another signed Chromium browser with Apple’s public-key credential entitlement.
- If a passkey request fails, turn off **Use helper for passkey requests** to use the current browser’s normal flow.
- macOS may show folder-access or app-management prompts when the selected browser starts. The helper does not modify browser apps and cannot suppress these prompts.

To remove the app and browser registrations, choose **Remove Helper** in the app. To unregister just the browser hosts, run `./native/unregister-password-helper.sh`.
