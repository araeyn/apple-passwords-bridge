// Route explicit WebAuthn ceremonies through the companion helper when it is
// available. Conditional passkey requests stay with the browser so its native
// autofill UI remains in control; the existing toggle only hides those requests.
(() => {
  const CHANNEL = "openpasswords:passkeys:v1";
  const BINARY_TAG = "__openPasswordsBufferSource";
  const TIMEOUT_NAME = "NotAllowedError";
  const HELPER_REQUEST_TIMEOUT_MS = 310_000;
  const USER_INTENT_WINDOW_MS = 60_000;
  const pending = new Map();
  const credentials = navigator.credentials;
  if (!credentials || typeof credentials.get !== "function" || typeof credentials.create !== "function") return;
  if (window.__openPasswordsPasskeyShimV1) return;
  window.__openPasswordsPasskeyShimV1 = true;

  const nativeGet = credentials.get.bind(credentials);
  const nativeCreate = credentials.create.bind(credentials);
  const nativeConditionalAvailable =
    typeof window.PublicKeyCredential?.isConditionalMediationAvailable === "function"
      ? window.PublicKeyCredential.isConditionalMediationAvailable.bind(window.PublicKeyCredential)
      : null;
  let hideConditionalPasskeys = false;
  let usePasskeyHelper = true;
  let lastTrustedInteractionAt = 0;

  function recordTrustedInteraction(event) {
    if (event.isTrusted) lastTrustedInteractionAt = Date.now();
  }

  for (const type of ["pointerdown", "keydown", "touchstart", "click", "submit"]) {
    document.addEventListener(type, recordTrustedInteraction, true);
  }

  function hasRecentUserIntent() {
    if (navigator.userActivation?.isActive) return true;
    const age = Date.now() - lastTrustedInteractionAt;
    return age >= 0 && age <= USER_INTENT_WINDOW_MS;
  }

  addEventListener("openpasswords:hide-passkeys-on", () => (hideConditionalPasskeys = true));
  addEventListener("openpasswords:hide-passkeys-off", () => (hideConditionalPasskeys = false));
  addEventListener("openpasswords:helper-passkeys-on", () => (usePasskeyHelper = true));
  addEventListener("openpasswords:helper-passkeys-off", () => (usePasskeyHelper = false));
  dispatchEvent(new Event("openpasswords:passkey-settings-request"));

  if (nativeConditionalAvailable) {
    try {
      window.PublicKeyCredential.isConditionalMediationAvailable = () =>
        usePasskeyHelper ? Promise.resolve(false) : nativeConditionalAvailable();
    } catch (_) {}
  }

  function makeError(name, message) {
    try {
      return new DOMException(message || name, name || "NotAllowedError");
    } catch (_) {
      const error = new Error(message || name || "WebAuthn request failed");
      error.name = name || "NotAllowedError";
      return error;
    }
  }

  function helperUnavailable() {
    return makeError(
      "NotAllowedError",
      "The passkey helper couldn't complete this request. Turn off Use passkey helper to use this browser's native passkey flow.",
    );
  }

  function sourceBytes(value) {
    if (!value || typeof value !== "object") return null;
    const tag = Object.prototype.toString.call(value);
    try {
      if (tag === "[object ArrayBuffer]" || tag === "[object SharedArrayBuffer]") return new Uint8Array(value);
      if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    } catch (_) {}
    return null;
  }

  function bytesToBase64URL(bytes) {
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64URLToBytes(value) {
    const base64 = String(value).replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function bytesToArrayBuffer(bytes) {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }

  function encodeBufferSources(value, ancestors = new WeakSet()) {
    const bytes = sourceBytes(value);
    if (bytes) return { [BINARY_TAG]: true, data: bytesToBase64URL(bytes) };
    if (value === null || typeof value !== "object") {
      if (typeof value === "function" || typeof value === "symbol" || typeof value === "bigint") return undefined;
      return value;
    }
    if (ancestors.has(value)) throw new TypeError("cyclic WebAuthn options");
    ancestors.add(value);
    let result;
    if (Array.isArray(value)) {
      result = value.map((item) => encodeBufferSources(item, ancestors));
    } else {
      result = {};
      for (const key of Object.keys(value)) {
        if (key === "signal") continue;
        const item = encodeBufferSources(value[key], ancestors);
        if (item !== undefined) result[key] = item;
      }
    }
    ancestors.delete(value);
    return result;
  }

  function newRequestID() {
    if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function postCancel(id) {
    try {
      window.postMessage({ channel: CHANNEL, type: "cancel", id }, location.origin);
    } catch (_) {}
  }

  function requestHelper(kind, options) {
    const origin = location.origin;
    if (!origin || origin === "null" || !options?.publicKey || typeof window.postMessage !== "function") {
      return Promise.reject(helperUnavailable());
    }

    let serializedOptions;
    try {
      serializedOptions = encodeBufferSources({
        publicKey: options.publicKey,
        ...(options.mediation !== undefined ? { mediation: options.mediation } : {}),
      });
    } catch (_) {
      return Promise.reject(helperUnavailable());
    }

    const id = newRequestID();
    const signal = options.signal;
    if (signal?.aborted) return Promise.reject(makeError("AbortError", "The operation was aborted."));

    return new Promise((resolve, reject) => {
      let settled = false;
      let timer = 0;
      const cleanup = () => {
        clearTimeout(timer);
        pending.delete(id);
        if (signal && abortHandler) signal.removeEventListener("abort", abortHandler);
        removeEventListener("message", onResponse);
      };
      const finish = (callback, value, cancel = false) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (cancel) postCancel(id);
        callback(value);
      };
      const abortHandler = () => finish(reject, makeError("AbortError", "The operation was aborted."), true);
      const fallbackToNative = (reason) => {
        console.warn("[Open Passwords] Passkey helper unavailable; using this browser's passkey flow.", reason);
        try {
          finish(resolve, (kind === "get" ? nativeGet : nativeCreate)(options));
        } catch (error) {
          finish(reject, error);
        }
      };
      const onResponse = (event) => {
        if (event.source !== window || event.origin !== origin) return;
        const message = event.data;
        if (!message || message.channel !== CHANNEL || message.type !== "response" || message.id !== id) return;
        const response = message.response;
        if (response?.reason === "native-messaging-permission-required") {
          // Let the selected browser make its own activation decision if the
          // helper has not been connected.
          fallbackToNative(response.reason);
          return;
        }
        if (response?.unavailable === true || response?.available === false || response?.error?.unavailable === true) {
          fallbackToNative(response.reason || "helper-unavailable");
          return;
        }
        if (response?.error) {
          const error = typeof response.error === "string" ? { message: response.error } : response.error;
          if (error.name === "NotSupportedError") {
            fallbackToNative(error.message || "helper-not-supported");
            return;
          }
          finish(reject, makeError(error.name || "NotAllowedError", error.message || "The passkey request failed."));
          return;
        }
        try {
          finish(resolve, reconstructCredential(kind, response));
        } catch (error) {
          finish(reject, makeError(error.name || TIMEOUT_NAME, error.message || "The helper returned an invalid passkey response."));
        }
      };

      pending.set(id, { abort: abortHandler });
      addEventListener("message", onResponse);
      if (signal) signal.addEventListener("abort", abortHandler, { once: true });
      // Include cold browser startup time. The relying-party timeout applies to
      // its WebAuthn ceremony, not to starting this separate helper browser.
      timer = setTimeout(() => finish(reject, makeError(TIMEOUT_NAME, "The passkey request timed out."), true), HELPER_REQUEST_TIMEOUT_MS);
      try {
        window.postMessage({ channel: CHANNEL, type: "request", id, kind, origin, options: serializedOptions }, origin);
      } catch (_) {
        finish(reject, helperUnavailable(), true);
      }
    });
  }

  addEventListener("pagehide", () => {
    for (const operation of pending.values()) operation.abort();
  });

  function fromBase64URLOrBuffer(value, field, nullable = false) {
    if (value == null && nullable) return null;
    const tagged = value && typeof value === "object" && value[BINARY_TAG] === true ? value.data : value;
    const bytes = sourceBytes(tagged);
    if (bytes) return bytesToArrayBuffer(bytes);
    if (typeof tagged !== "string") throw new TypeError(`missing or invalid ${field}`);
    return bytesToArrayBuffer(base64URLToBytes(tagged));
  }

  function decodeExtensionResults(value, path = []) {
    if (value == null || typeof value !== "object") {
      const isBinaryExtension =
        (path.length >= 3 && path[path.length - 3] === "prf" && path[path.length - 2] === "results" &&
          (path[path.length - 1] === "first" || path[path.length - 1] === "second")) ||
        (path.length >= 2 && path[path.length - 2] === "largeBlob" && path[path.length - 1] === "blob");
      if (typeof value === "string" && isBinaryExtension) return fromBase64URLOrBuffer(value, path.join("."));
      return value;
    }
    if (value[BINARY_TAG] === true) return fromBase64URLOrBuffer(value, path.join("."));
    if (Array.isArray(value)) return value.map((item, index) => decodeExtensionResults(item, [...path, String(index)]));
    const result = {};
    for (const [key, item] of Object.entries(value)) result[key] = decodeExtensionResults(item, [...path, key]);
    return result;
  }

  function extensionResultsToJSON(value, path = []) {
    if (value == null || typeof value !== "object") return value;
    const bytes = sourceBytes(value);
    if (bytes) return bytesToBase64URL(bytes);
    if (Array.isArray(value)) return value.map((item, index) => extensionResultsToJSON(item, [...path, String(index)]));
    const result = {};
    for (const [key, item] of Object.entries(value)) result[key] = extensionResultsToJSON(item, [...path, key]);
    return result;
  }

  function defineValue(target, key, value) {
    Object.defineProperty(target, key, { configurable: true, enumerable: true, value });
  }

  function reconstructCredential(kind, outerResponse) {
    if (!outerResponse || typeof outerResponse !== "object") throw new TypeError("missing passkey response");
    let credential = outerResponse.credential || outerResponse.publicKeyCredential || outerResponse;
    if (typeof credential === "string") credential = JSON.parse(credential);
    if (typeof credential?.responseJson === "string") credential = JSON.parse(credential.responseJson);
    if (!credential || typeof credential !== "object") throw new TypeError("invalid passkey credential");

    const rawId = fromBase64URLOrBuffer(credential.rawId ?? credential.id, "rawId");
    const responseData = credential.response;
    if (!responseData || typeof responseData !== "object") throw new TypeError("missing authenticator response");
    const clientDataJSON = fromBase64URLOrBuffer(responseData.clientDataJSON, "clientDataJSON");
    const responsePrototype = kind === "create"
      ? window.AuthenticatorAttestationResponse?.prototype
      : window.AuthenticatorAssertionResponse?.prototype;
    const authenticatorResponse = Object.create(responsePrototype || Object.prototype);
    defineValue(authenticatorResponse, "clientDataJSON", clientDataJSON);
    authenticatorResponse.toJSON = function () {
      const json = { clientDataJSON: bytesToBase64URL(new Uint8Array(clientDataJSON)) };
      if (kind === "create") {
        json.attestationObject = bytesToBase64URL(new Uint8Array(authenticatorResponse.attestationObject));
        if (authenticatorResponse.authenticatorData) json.authenticatorData = bytesToBase64URL(new Uint8Array(authenticatorResponse.authenticatorData));
        if (authenticatorResponse.publicKey) json.publicKey = bytesToBase64URL(new Uint8Array(authenticatorResponse.publicKey));
        if (authenticatorResponse.publicKeyAlgorithm != null) json.publicKeyAlgorithm = authenticatorResponse.publicKeyAlgorithm;
        if (typeof authenticatorResponse.getTransports === "function") json.transports = authenticatorResponse.getTransports();
      } else {
        json.authenticatorData = bytesToBase64URL(new Uint8Array(authenticatorResponse.authenticatorData));
        json.signature = bytesToBase64URL(new Uint8Array(authenticatorResponse.signature));
        json.userHandle = authenticatorResponse.userHandle == null ? null : bytesToBase64URL(new Uint8Array(authenticatorResponse.userHandle));
      }
      return json;
    };

    if (kind === "create") {
      const attestationObject = fromBase64URLOrBuffer(responseData.attestationObject, "attestationObject");
      const authenticatorData = responseData.authenticatorData == null ? null : fromBase64URLOrBuffer(responseData.authenticatorData, "authenticatorData");
      const publicKey = responseData.publicKey == null ? null : fromBase64URLOrBuffer(responseData.publicKey, "publicKey");
      const publicKeyAlgorithm = responseData.publicKeyAlgorithm == null ? null : Number(responseData.publicKeyAlgorithm);
      const transports = Array.isArray(responseData.transports) ? responseData.transports.filter((item) => typeof item === "string") : [];
      defineValue(authenticatorResponse, "attestationObject", attestationObject);
      if (authenticatorData) defineValue(authenticatorResponse, "authenticatorData", authenticatorData);
      if (publicKey) defineValue(authenticatorResponse, "publicKey", publicKey);
      defineValue(authenticatorResponse, "publicKeyAlgorithm", publicKeyAlgorithm);
      authenticatorResponse.getTransports = () => transports.slice();
      authenticatorResponse.getAuthenticatorData = () => authenticatorData;
      authenticatorResponse.getPublicKey = () => publicKey;
      authenticatorResponse.getPublicKeyAlgorithm = () => publicKeyAlgorithm;
    } else if (kind === "get") {
      defineValue(authenticatorResponse, "authenticatorData", fromBase64URLOrBuffer(responseData.authenticatorData, "authenticatorData"));
      defineValue(authenticatorResponse, "signature", fromBase64URLOrBuffer(responseData.signature, "signature"));
      defineValue(authenticatorResponse, "userHandle", fromBase64URLOrBuffer(responseData.userHandle, "userHandle", true));
    } else {
      throw new TypeError("unsupported passkey operation");
    }

    const extensionResults = decodeExtensionResults(credential.clientExtensionResults || {});
    const publicKeyCredential = Object.create(window.PublicKeyCredential?.prototype || Object.prototype);
    defineValue(publicKeyCredential, "id", typeof credential.id === "string" ? credential.id : bytesToBase64URL(new Uint8Array(rawId)));
    defineValue(publicKeyCredential, "rawId", rawId);
    defineValue(publicKeyCredential, "type", credential.type || "public-key");
    defineValue(publicKeyCredential, "authenticatorAttachment", credential.authenticatorAttachment ?? "platform");
    defineValue(publicKeyCredential, "response", authenticatorResponse);
    publicKeyCredential.getClientExtensionResults = () => extensionResults;
    publicKeyCredential.toJSON = () => ({
      id: publicKeyCredential.id,
      rawId: bytesToBase64URL(new Uint8Array(publicKeyCredential.rawId)),
      type: publicKeyCredential.type,
      authenticatorAttachment: publicKeyCredential.authenticatorAttachment,
      response: authenticatorResponse.toJSON(),
      clientExtensionResults: extensionResultsToJSON(extensionResults),
    });
    return publicKeyCredential;
  }

  function hideConditionalRequest(options) {
    return new Promise((_, reject) => {
      const signal = options?.signal;
      if (!signal) return;
      const abort = () => reject(makeError("AbortError", "The operation was aborted."));
      if (signal.aborted) abort();
      else signal.addEventListener("abort", abort, { once: true });
    });
  }

  function wrap(kind, original) {
    return function (options) {
      const publicKey = options && options.publicKey;
      if (!publicKey) return original(options);

      const conditional = kind === "get" && options.mediation === "conditional";
      if (conditional) return hideConditionalPasskeys ? hideConditionalRequest(options) : original(options);
      if (!usePasskeyHelper) return original(options);
      // Some sites fetch a challenge after the click, then call WebAuthn once
      // transient activation has expired. Accept a recent trusted interaction
      // while still keeping page-load scripts on the browser's native path.
      if (!hasRecentUserIntent()) return original(options);
      return requestHelper(kind, options);
    };
  }

  try {
    credentials.get = wrap("get", nativeGet);
    credentials.create = wrap("create", nativeCreate);
  } catch (_) {
    // If the browser exposes a non-writable CredentialContainer, native WebAuthn
    // remains available without the optional helper bridge.
  }
})();
