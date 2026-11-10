// Relay settings and explicit WebAuthn requests between the page world and the
// extension worker. The worker owns native messaging; this isolated-world bridge
// never reads or stores credential material.
(() => {
  if (globalThis.__openPasswordsPasskeyBridgeV1) return;
  globalThis.__openPasswordsPasskeyBridgeV1 = true;

  const PASSKEY_CHANNEL = "openpasswords:passkeys:v1";
  const settings = { usePasskeyHelper: true };
  const publishSettings = () => dispatchEvent(new Event(`openpasswords:helper-passkeys-${settings.usePasskeyHelper ? "on" : "off"}`));

  // The MAIN-world shim asks after installing its listeners so it cannot miss
  // the initial setting if storage responds before the other content script.
  addEventListener("openpasswords:passkey-settings-request", publishSettings);
  chrome.storage?.local?.get({ usePasskeyHelper: true }, (data) => {
    settings.usePasskeyHelper = !!data.usePasskeyHelper;
    publishSettings();
  });
  chrome.storage?.onChanged?.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes.usePasskeyHelper) settings.usePasskeyHelper = !!changes.usePasskeyHelper.newValue;
    if (changes.usePasskeyHelper) publishSettings();
  });

  const cancelled = new Set();
  const cancelledCleanup = new Map();
  const activeRequests = new Set();
  const markCancelled = (id) => {
    if (typeof id !== "string" || !activeRequests.has(id)) return;
    cancelled.add(id);
    clearTimeout(cancelledCleanup.get(id));
    cancelledCleanup.set(id, setTimeout(() => {
      cancelled.delete(id);
      cancelledCleanup.delete(id);
    }, 300_000));
    try {
      chrome.runtime.sendMessage({ type: "cancelPasskeyRequest", requestId: id }, () => {
        void chrome.runtime.lastError;
      });
    } catch (_) {}
  };

  const sendUnavailable = (id, reason) => {
    window.postMessage({
      channel: PASSKEY_CHANNEL,
      type: "response",
      id,
      response: { available: false, reason },
    }, location.origin);
  };

  addEventListener("message", (event) => {
    if (event.source !== window || event.origin !== location.origin) return;
    const message = event.data;
    if (!message || message.channel !== PASSKEY_CHANNEL) return;

    if (message.type === "cancel") {
      markCancelled(message.id);
      return;
    }

    if (message.type !== "request") return;
    const { id, kind, origin, options } = message;
    if (typeof id !== "string" || !id || id.length > 128 || (kind !== "get" && kind !== "create") || origin !== location.origin) {
      sendUnavailable(typeof id === "string" && id.length <= 128 ? id : "", "invalid-request");
      return;
    }
    if (activeRequests.has(id) || cancelled.has(id)) return;
    activeRequests.add(id);
    try {
      chrome.runtime.sendMessage({ type: "passkeyRequest", requestId: id, kind, origin, options }, (reply) => {
        const runtimeError = chrome.runtime.lastError?.message;
        activeRequests.delete(id);
        if (cancelled.has(id)) {
          cancelled.delete(id);
          clearTimeout(cancelledCleanup.get(id));
          cancelledCleanup.delete(id);
          return;
        }
        if (runtimeError || !reply) {
          sendUnavailable(id, runtimeError || "no-response");
          return;
        }
        if (reply.requestId !== undefined && reply.requestId !== id) {
          sendUnavailable(id, "mismatched-request-id");
          return;
        }
        window.postMessage({
          channel: PASSKEY_CHANNEL,
          type: "response",
          id,
          response: Object.prototype.hasOwnProperty.call(reply, "response") ? reply.response : reply,
        }, location.origin);
      });
    } catch (error) {
      activeRequests.delete(id);
      sendUnavailable(id, error?.message || "extension-unavailable");
    }
  });

  addEventListener("pagehide", () => {
    for (const id of activeRequests) markCancelled(id);
  });
})();
