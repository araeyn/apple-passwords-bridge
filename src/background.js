// Owns the on-demand native connection and SRP session. The open native port keeps
// this worker alive while connected; one-shot timers only expire short-lived data
// and disconnect the helper after the user's idle limit.

import { ApplePasswords, State } from "./protocol.js";

const client = new ApplePasswords();

client.onStateChange((s) => {
  // any state other than unlocked means the session/keys are gone - drop the plaintext cache
  if (s !== State.Unlocked) pwCacheClear();
  broadcast({ type: "state", state: s });
  scheduleMaintenance();
});

function broadcast(msg) {
  chrome.runtime.sendMessage(msg).catch(() => {});
}

// most-recently-used login per host (in-memory), so the dropdown floats your usual account up
const mruByHost = new Map(); // host -> [username lowercased, most recent first]
function recordMru(host, username) {
  if (!host || !username) return;
  const u = username.toLowerCase();
  const arr = (mruByHost.get(host) || []).filter((x) => x !== u);
  arr.unshift(u);
  mruByHost.set(host, arr.slice(0, 10));
}
function orderByMru(host, logins) {
  const order = mruByHost.get(host);
  if (!order || !order.length) return logins;
  const rank = (u) => {
    const i = order.indexOf((u || "").toLowerCase());
    return i === -1 ? Infinity : i;
  };
  // stable sort keeps the helper's own order for anything not in the MRU list
  return [...logins].sort((a, b) => rank(a.username) - rank(b.username));
}

// which account a submitted password attaches to ("" lets the native sheet ask, null saves nothing); in the background so a redirect cant lose it
function pickSaveTarget({ host, existing, detected, generated, newPwCtx }) {
  const matched = detected && existing.find((u) => u.toLowerCase() === detected.toLowerCase());
  // update only on a new password, stay quiet on a plain re-login
  if (matched) return generated || newPwCtx ? matched : null;
  if (detected) return detected;
  // no username on a reset with saved account(s): attach to the MRU one, apple's sheet lets the user re-pick
  if (newPwCtx && existing.length) {
    return orderByMru(host, existing.map((u) => ({ username: u })))[0].username;
  }
  if (generated) return "";
  return null;
}

// new-password saves that arrived while locked; a reset can navigate away, so stash and flush on unlock
const pendingSaves = [];
const PENDING_SAVE_TTL_MS = 10 * 60_000;
let pendingSaveFlush = false;
const pendingSavesReady = (async () => {
  try {
    if (typeof chrome.storage.session?.setAccessLevel === "function") {
      await chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
    }
    const saved = await chrome.storage.session.get({ pendingSaves: [] });
    if (Array.isArray(saved.pendingSaves)) {
      pendingSaves.push(
        ...saved.pendingSaves
          .filter((item) =>
            item &&
            typeof item === "object" &&
            typeof item.host === "string" &&
            typeof item.frameUrl === "string" &&
            typeof item.password === "string" &&
            Number.isFinite(item.queuedAt),
          )
          .slice(-10),
      );
    }
    prunePendingSaves();
  } catch (_) {
    // Session storage is available on supported Chromium versions. If it fails,
    // keep saves volatile in the worker rather than writing plaintext to disk.
  } finally {
    scheduleMaintenance();
  }
})();

function persistPendingSaves() {
  try {
    return chrome.storage.session?.set({ pendingSaves: [...pendingSaves] }).catch(() => {});
  } catch (_) {
    return Promise.resolve();
  }
}

function prunePendingSaves(now = Date.now()) {
  let changed = false;
  for (let i = pendingSaves.length - 1; i >= 0; i--) {
    if (now - pendingSaves[i].queuedAt >= PENDING_SAVE_TTL_MS) {
      pendingSaves.splice(i, 1);
      changed = true;
    }
  }
  if (changed) persistPendingSaves();
}

async function queuePendingSave(save) {
  await pendingSavesReady;
  prunePendingSaves();
  const k = `${save.host} ${(save.detected || "").toLowerCase()}`;
  const i = pendingSaves.findIndex((p) => `${p.host} ${(p.detected || "").toLowerCase()}` === k);
  if (i >= 0) pendingSaves.splice(i, 1); // newest wins
  pendingSaves.push({ ...save, queuedAt: Date.now() });
  while (pendingSaves.length > 10) pendingSaves.shift();
  await persistPendingSaves();
  scheduleMaintenance();
}
async function flushPendingSaves() {
  await pendingSavesReady;
  prunePendingSaves();
  if (!client.ready || !pendingSaves.length) {
    scheduleMaintenance();
    return;
  }
  const batch = pendingSaves.splice(0);
  pendingSaveFlush = true;
  try {
    for (const s of batch) {
      try {
        if (Date.now() - s.queuedAt >= PENDING_SAVE_TTL_MS) continue;
        let existing = [];
        try {
          existing = (await client.getLoginNamesForURL(s.tabId, s.frameUrl))
            .map((l) => l.username)
            .filter(Boolean);
        } catch {}
        const target = pickSaveTarget({ ...s, existing });
        if (target === null) continue;
        await client.saveLogin(s.tabId, s.frameUrl, target, s.password);
      } catch {}
    }
  } finally {
    pendingSaveFlush = false;
    await persistPendingSaves();
    scheduleMaintenance();
  }
}

// collapse identical-looking usernames: trailing/leading space, zero-width chars, case, and
// unicode composition all equal. keeps internal spaces so distinct usernames arent merged
function normUsername(u) {
  return (u || "")
    .normalize("NFC")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .trim()
    .toLowerCase();
}

// helper returns the same username several times (www + apex entries, or a stray-space dupe).
// fills look up by username, so extra rows only ever fetch the same credential - drop them
function uniqueByUsername(logins) {
  const seen = new Set();
  return logins.filter((l) => {
    const k = normUsername(l.username);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// what we last filled per tab, so a popup refresh can re-fill the page with a fresh read
const lastFillByTab = new Map(); // tabId -> { host, username }

// short-lived cache of decrypted passwords so re-filling the same login skips a second Touch
// ID (apple prompts every read). plaintext in worker memory up to the TTL, cleared on lock
const PW_CACHE_TTL_MS = 120_000; // 2 minutes
const pwCache = new Map(); // `${host}\n${username lowercased}` -> { cred, at }
function pwCacheKey(host, username) {
  return `${host}\n${(username || "").toLowerCase()}`;
}
function pwCacheGet(host, username) {
  const k = pwCacheKey(host, username);
  const hit = pwCache.get(k);
  if (!hit) return null;
  if (Date.now() - hit.at >= PW_CACHE_TTL_MS) {
    pwCache.delete(k);
    scheduleMaintenance();
    return null;
  }
  return hit.cred;
}
function pwCacheSet(host, cred) {
  if (!host || !cred?.username) return;
  pwCache.set(pwCacheKey(host, cred.username), { cred, at: Date.now() });
  scheduleMaintenance();
}
function pwCacheClear() {
  pwCache.clear();
  scheduleMaintenance();
}
function pwCachePrune(now = Date.now()) {
  for (const [key, hit] of pwCache) {
    if (now - hit.at >= PW_CACHE_TTL_MS) pwCache.delete(key);
  }
}

// stuck native call shouldnt leave a UI waiter (inline PIN box) hanging forever
function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(label || "timed out")), ms)),
  ]);
}

// Clear the repeating alarm left by older versions. Native messaging already
// keeps this worker alive for an active connection, so no heartbeat is needed.
const KEEPALIVE_ALARM = "open-passwords-keepalive";
const MAINTENANCE_ALARM = "open-passwords-maintenance";
const PASSKEY_DEFAULT_MIGRATION = "passkeyHelperDefaultOnV050";
chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.clear(KEEPALIVE_ALARM);
  chrome.storage.local.get({ [PASSKEY_DEFAULT_MIGRATION]: false }, (settings) => {
    if (settings[PASSKEY_DEFAULT_MIGRATION]) return;
    chrome.storage.local.set({
      usePasskeyHelper: true,
      [PASSKEY_DEFAULT_MIGRATION]: true,
    });
  });
});
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === MAINTENANCE_ALARM) runMaintenance();
});

const DEFAULT_HELPER_IDLE_MINUTES = 10;
const ALLOWED_HELPER_IDLE_MINUTES = new Set([0, 5, 10, 20, 60]);
let helperIdleMinutes = DEFAULT_HELPER_IDLE_MINUTES;
let lastHelperActivityAt = 0;
let maintenanceTimer = null;
let activeMessages = 0;

chrome.storage.local.get({ helperIdleMinutes: DEFAULT_HELPER_IDLE_MINUTES }, (values) => {
  const configured = Number(values.helperIdleMinutes);
  if (ALLOWED_HELPER_IDLE_MINUTES.has(configured)) helperIdleMinutes = configured;
  scheduleMaintenance();
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.helperIdleMinutes) return;
  const configured = Number(changes.helperIdleMinutes.newValue);
  if (ALLOWED_HELPER_IDLE_MINUTES.has(configured)) {
    helperIdleMinutes = configured;
    scheduleMaintenance();
  }
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.usePasskeyHelper || changes.usePasskeyHelper.newValue === true) return;
  for (const entry of passkeyRequests.values()) {
    try {
      entry.port?.postMessage({ type: "cancel", requestId: entry.requestId });
    } catch (_) {}
  }
});

function scheduleMaintenance() {
  if (maintenanceTimer !== null) clearTimeout(maintenanceTimer);
  maintenanceTimer = null;

  const deadlines = [];
  for (const hit of pwCache.values()) deadlines.push(hit.at + PW_CACHE_TTL_MS);
  for (const save of pendingSaves) deadlines.push(save.queuedAt + PENDING_SAVE_TTL_MS);

  const helperBusy = activeMessages > 0 || pendingSaveFlush || client.hasPendingRequests;
  if (
    client.port &&
    helperIdleMinutes > 0 &&
    pendingSaves.length === 0 &&
    !helperBusy &&
    lastHelperActivityAt > 0
  ) {
    deadlines.push(lastHelperActivityAt + helperIdleMinutes * 60_000);
  }

  if (!deadlines.length) {
    chrome.alarms.clear(MAINTENANCE_ALARM);
    return;
  }
  const when = Math.max(Date.now() + 1, Math.min(...deadlines));
  maintenanceTimer = setTimeout(runMaintenance, Math.max(1, when - Date.now()));
  // Timers are efficient while the worker is active; a one-shot alarm also
  // wakes it to expire session-only queued saves or disconnect an idle helper.
  try {
    const alarm = chrome.alarms.create(MAINTENANCE_ALARM, { when });
    alarm?.catch?.(() => {});
  } catch (_) {}
}

function runMaintenance() {
  if (maintenanceTimer !== null) clearTimeout(maintenanceTimer);
  maintenanceTimer = null;
  const now = Date.now();
  pwCachePrune(now);
  prunePendingSaves(now);

  const helperBusy = activeMessages > 0 || pendingSaveFlush || client.hasPendingRequests;
  const idleDeadline = lastHelperActivityAt + helperIdleMinutes * 60_000;
  if (
    client.port &&
    helperIdleMinutes > 0 &&
    pendingSaves.length === 0 &&
    !helperBusy &&
    lastHelperActivityAt > 0 &&
    now >= idleDeadline
  ) {
    lastHelperActivityAt = 0;
    pwCacheClear();
    client.disconnect();
  }
  scheduleMaintenance();
}

function noteHelperActivity() {
  lastHelperActivityAt = Date.now();
  scheduleMaintenance();
}

async function ensureConnected() {
  const allowed = await chrome.permissions.contains({ permissions: ["nativeMessaging"] }).catch(() => false);
  if (!allowed) {
    lastHelperActivityAt = 0;
    client.disconnect();
    scheduleMaintenance();
    return false;
  }
  noteHelperActivity();
  if (client.state === State.Disconnected || client.state === State.NoHelper) {
    try {
      await client.connect();
    } catch (e) {
      // surfaced via state change (NoHelper / Disconnected)
    }
  }
  scheduleMaintenance();
}

// only the extension's own popup may drive privileged actions (content messages carry sender.tab, the popup never does)
function isFromOwnUi(sender) {
  return sender.id === chrome.runtime.id && sender.tab === undefined;
}

// resolve from the real active tab, never from caller input
async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function registrableHost(u) {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// loopback (secure context) and reserved .test / .localhost TLDs (RFC 6761, never real
// sites) are the only non-HTTPS origins we treat as fillable/saveable
function isLocalDevHost(host) {
  return (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "[::1]" ||
    host?.endsWith(".localhost") ||
    host?.endsWith(".test")
  );
}

function isSupportedCredentialUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || (url.protocol === "http:" && isLocalDevHost(url.hostname.toLowerCase()));
  } catch {
    return false;
  }
}

// messages a content script may send - only the sender's own tab/origin, never return a password to the page
const CONTENT_ALLOWED = new Set([
  "inlineLogins",
  "inlineFill",
  "openPopup",
  "resolveSave",
  "passkeyRequest",
  "cancelPasskeyRequest",
]);
const PASSKEY_NATIVE_HOST = "com.openpasswords.passkeys";
const passkeyRequests = new Map();

function passkeyRequestKey(sender, requestId) {
  return `${sender.tab?.id ?? "-"}:${sender.frameId ?? "-"}:${requestId}`;
}

function respondPasskeyUnavailable(requestId, reason) {
  return { requestId, response: { available: false, unavailable: true, reason } };
}

async function startPasskeyRequest(msg, sender, sendResponse) {
  const requestId = msg.requestId;
  const pageUrl = sender.url;
  if (
    typeof requestId !== "string" ||
    requestId.length > 128 ||
    !["get", "create"].includes(msg.kind) ||
    sender.frameId !== 0 ||
    !isSupportedCredentialUrl(pageUrl)
  ) {
    sendResponse(respondPasskeyUnavailable(typeof requestId === "string" ? requestId : "", "invalid-request"));
    return;
  }
  let helperEnabled = false;
  try {
    const settings = await chrome.storage.local.get({ usePasskeyHelper: true });
    helperEnabled = settings.usePasskeyHelper === true;
  } catch (_) {}
  if (!helperEnabled) {
    sendResponse(respondPasskeyUnavailable(requestId, "passkey-helper-disabled"));
    return;
  }
  const nativeMessagingAllowed = await chrome.permissions.contains({ permissions: ["nativeMessaging"] }).catch(() => false);
  if (!nativeMessagingAllowed) {
    sendResponse(respondPasskeyUnavailable(requestId, "native-messaging-permission-required"));
    return;
  }
  let pageOrigin;
  try {
    pageOrigin = new URL(pageUrl).origin;
  } catch {
    sendResponse(respondPasskeyUnavailable(requestId, "invalid-origin"));
    return;
  }
  if (msg.origin !== pageOrigin || pageOrigin === "null") {
    sendResponse(respondPasskeyUnavailable(requestId, "origin-mismatch"));
    return;
  }
  if (!msg.options || typeof msg.options !== "object" || Array.isArray(msg.options)) {
    sendResponse(respondPasskeyUnavailable(requestId, "invalid-options"));
    return;
  }
  let optionsSize;
  try {
    optionsSize = new TextEncoder().encode(JSON.stringify(msg.options)).byteLength;
  } catch {
    sendResponse(respondPasskeyUnavailable(requestId, "invalid-options"));
    return;
  }
  if (optionsSize > 512 * 1024) {
    sendResponse(respondPasskeyUnavailable(requestId, "request-too-large"));
    return;
  }

  const key = passkeyRequestKey(sender, requestId);
  if (passkeyRequests.has(key)) {
    sendResponse(respondPasskeyUnavailable(requestId, "duplicate-request"));
    return;
  }
  // The broker starts a dedicated signed browser process and window. Keep it
  // to one ceremony at a time so a page cannot multiply native processes.
  if (passkeyRequests.size >= 1) {
    sendResponse(respondPasskeyUnavailable(requestId, "passkey-helper-busy"));
    return;
  }

  let port;
  let settled = false;
  let responseTimer = 0;
  const entry = {
    port: null,
    tabId: sender.tab?.id,
    frameId: sender.frameId,
    pageUrl,
    origin: pageOrigin,
    requestId,
  };
  passkeyRequests.set(key, entry);
  const finish = (response) => {
    if (settled) return;
    settled = true;
    clearTimeout(responseTimer);
    passkeyRequests.delete(key);
    if (entry.port) {
      try {
        entry.port.disconnect();
      } catch (_) {}
      entry.port = null;
    }
    sendResponse({ requestId, response });
    scheduleMaintenance();
  };

  try {
    port = chrome.runtime.connectNative(PASSKEY_NATIVE_HOST);
    entry.port = port;
  } catch (error) {
    finish({ available: false, unavailable: true, reason: String(error?.message || error) });
    return;
  }

  port.onMessage.addListener((reply) => {
    if (!reply || reply.requestId !== requestId) return;
    if (reply.error) finish({ error: reply.error });
    else if (reply.credential) finish({ available: true, credential: reply.credential });
    else finish({ available: false, unavailable: true, reason: "invalid-helper-response" });
  });
  port.onDisconnect.addListener(() => {
    const error = chrome.runtime.lastError?.message || "Passkey helper disconnected.";
    if (!settled) finish({ available: false, unavailable: true, reason: error });
  });
  responseTimer = setTimeout(() => {
    try {
      port.postMessage({ type: "cancel", requestId });
    } catch (_) {}
    finish({ error: { name: "NotAllowedError", message: "The passkey request timed out." } });
  }, 4 * 60_000);

  try {
    port.postMessage({ type: "request", requestId, kind: msg.kind, origin: pageOrigin, options: msg.options });
  } catch (error) {
    finish({ available: false, unavailable: true, reason: String(error?.message || error) });
  }
}

function cancelPasskeyRequest(msg, sender) {
  if (typeof msg.requestId !== "string") return;
  const key = passkeyRequestKey(sender, msg.requestId);
  const entry = passkeyRequests.get(key);
  if (!entry?.port) return;
  try {
    if (new URL(sender.url).origin !== entry.origin) return;
  } catch (_) {
    return;
  }
  try {
    entry.port.postMessage({ type: "cancel", requestId: msg.requestId });
  } catch (_) {}
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  activeMessages += 1;
  (async () => {
    try {
      // Content scripts are limited to the explicit allowlist above; all other messages are popup-only.
      const fromUi = isFromOwnUi(sender);
      const fromContent = sender.id === chrome.runtime.id && sender.tab !== undefined;
      if (!fromUi && !(fromContent && CONTENT_ALLOWED.has(msg?.type))) {
        sendResponse({ ok: false, error: "forbidden" });
        return;
      }

      switch (msg?.type) {
        case "openPopup": {
          // only a content-script click on a supported credential page may open the action popup
          if (!fromContent || !isSupportedCredentialUrl(sender.url)) {
            return sendResponse({ ok: false, error: "forbidden" });
          }
          if (typeof chrome.action?.openPopup !== "function") {
            return sendResponse({ ok: false, error: "popup opening is not supported by this browser" });
          }
          await chrome.action.openPopup();
          sendResponse({ ok: true });
          break;
        }

        case "passkeyRequest": {
          if (!fromContent || !isSupportedCredentialUrl(sender.url)) {
            return sendResponse(respondPasskeyUnavailable(msg.requestId, "forbidden"));
          }
          await startPasskeyRequest(msg, sender, sendResponse);
          return;
        }

        case "cancelPasskeyRequest": {
          if (!fromContent || !isSupportedCredentialUrl(sender.url)) {
            return sendResponse({ ok: false, error: "forbidden" });
          }
          cancelPasskeyRequest(msg, sender);
          sendResponse({ ok: true });
          break;
        }

        case "inlineLogins": {
          // login names only (no passwords) for the exact frame that asked, keyed to sender.url not the top tab
          const frameUrl = sender.url;
          if (!frameUrl) return sendResponse({ ok: false, error: "no frame" });
          if (!isSupportedCredentialUrl(frameUrl)) {
            return sendResponse({ ok: false, error: "refusing to list passwords on a non-HTTPS page" });
          }
          await ensureConnected();
          if (!client.ready) return sendResponse({ ok: true, locked: true, logins: [] });
          try {
            const logins = await client.getLoginNamesForURL(sender.tab?.id, frameUrl);
            sendResponse({
              ok: true,
              locked: false,
              logins: uniqueByUsername(orderByMru(registrableHost(frameUrl), logins)),
            });
          } catch {
            sendResponse({ ok: true, locked: false, logins: [] });
          }
          break;
        }

        case "inlineFill": {
          // fetch + fill for the requesting frame's own origin only (frameId), never broadcast - confused-deputy fix
          const frameUrl = sender.url;
          const frameId = sender.frameId;
          if (!frameUrl || sender.tab?.id == null || frameId == null) {
            return sendResponse({ ok: false, error: "no frame" });
          }
          const host = registrableHost(frameUrl);
          if (!isSupportedCredentialUrl(frameUrl)) {
            return sendResponse({ ok: false, error: "refusing to fill on a non-HTTPS frame" });
          }
          await ensureConnected();
          if (!client.ready) return sendResponse({ ok: true, locked: true, filled: false });
          // ignore caller-supplied loginName.sites, query by frame's own host
          // (handled in protocol.js); pass only username through
          const safeLogin = { username: msg.loginName?.username };
          // cache hit skips the helper read and its Touch ID; miss reads then caches
          let cred = pwCacheGet(host, safeLogin.username);
          if (!cred) {
            cred = await client.getPasswordForLoginName(sender.tab.id, frameUrl, safeLogin);
            if (cred) pwCacheSet(host, cred);
          }
          let filled = false;
          if (cred) {
            const resp = await chrome.tabs.sendMessage(
              sender.tab.id,
              {
                type: "fill",
                username: cred.username,
                password: cred.password,
                expectedHost: host,
              },
              { frameId }, // requesting frame only
            );
            filled = !!resp?.filled;
            if (filled) {
              recordMru(host, cred.username);
              lastFillByTab.set(sender.tab.id, { host, username: cred.username });
            }
          }
          sendResponse({ ok: true, filled });
          break;
        }

        case "resolveSave": {
          // resolve + save here in the background so a submit that navigates cant kill it; native sheet is still the write gate
          const frameUrl = sender.url;
          if (!frameUrl || sender.tab?.id == null) {
            return sendResponse({ ok: false, error: "no frame" });
          }
          const host = registrableHost(frameUrl);
          if (!isSupportedCredentialUrl(frameUrl)) {
            return sendResponse({ ok: false, error: "refusing to save from a non-HTTPS frame" });
          }
          if (!msg.password) return sendResponse({ ok: false, error: "no password" });
          const detected = (msg.username || "").trim();
          const generated = !!msg.generated;
          const newPwCtx = !!msg.newPwCtx;
          await ensureConnected();

          // locked: cant list or write - stash a new-password save for unlock, a plain re-login isnt worth deferring
          if (!client.ready) {
            if (generated || newPwCtx) {
              await queuePendingSave({
                host,
                frameUrl,
                tabId: sender.tab.id,
                detected,
                password: msg.password,
                generated,
                newPwCtx,
              });
            }
            return sendResponse({ ok: true, saved: false, locked: true });
          }

          let existing = [];
          try {
            existing = (await client.getLoginNamesForURL(sender.tab.id, frameUrl))
              .map((l) => l.username)
              .filter(Boolean);
          } catch {}
          const target = pickSaveTarget({ host, existing, detected, generated, newPwCtx });
          console.debug("[Open Passwords] resolveSave", {
            host,
            generated,
            newPwCtx,
            existingCount: existing.length,
          });
          if (target === null) return sendResponse({ ok: true, saved: false, skipped: true });
          await client.saveLogin(sender.tab.id, frameUrl, target, msg.password);
          sendResponse({ ok: true, saved: true });
          break;
        }

        case "getState":
          await ensureConnected();
          sendResponse({ ok: true, state: client.state });
          break;

        case "connect":
          await ensureConnected();
          sendResponse({ ok: true, state: client.state });
          break;

        case "requestChallenge":
          // top frame (or popup) only, so a hostile sub-frame cant spam native prompts
          if (fromContent && sender.frameId !== 0) return sendResponse({ ok: false, error: "forbidden" });
          await ensureConnected();
          await withTimeout(client.requestChallenge(), 8000, "challenge timed out");
          sendResponse({ ok: true, state: client.state });
          break;

        case "verifyPin":
          if (fromContent && sender.frameId !== 0) return sendResponse({ ok: false, error: "forbidden" });
          await ensureConnected();
          if (!client.session) return sendResponse({ ok: false, error: "Passwords helper is not connected.", state: client.state });
          if (client.session.serverPublicKey === undefined || client.session.salt === undefined) {
            await withTimeout(client.requestChallenge(), 8000, "challenge timed out");
            return sendResponse({
              ok: false,
              error: "A fresh code was requested on your Mac. Enter that code to continue.",
              state: client.state,
            });
          }
          // cap so a non-responding helper cant leave the inline PIN box stuck
          await withTimeout(client.verifyPin(msg.pin), 8000, "verification timed out");
          sendResponse({ ok: true, state: client.state });
          // just unlocked - complete any saves stashed while locked
          if (client.ready) await flushPendingSaves();
          break;

        case "getLogins": {
          // real active tab's URL, never caller-supplied
          const tab = await activeTab();
          if (!tab?.url) return sendResponse({ ok: false, error: "no active tab" });
          if (!isSupportedCredentialUrl(tab.url)) {
            return sendResponse({ ok: false, error: "refusing to list passwords on a non-HTTPS page" });
          }
          await ensureConnected();
          if (!client.ready) return sendResponse({ ok: true, logins: [] });
          const logins = await client.getLoginNamesForURL(tab.id, tab.url);
          sendResponse({ ok: true, logins: uniqueByUsername(orderByMru(registrableHost(tab.url), logins)) });
          break;
        }

        case "fillOnPage": {
          const tab = await activeTab();
          if (!tab?.url) return sendResponse({ ok: false, error: "no active tab" });
          const host = registrableHost(tab.url);
          if (!isSupportedCredentialUrl(tab.url)) {
            return sendResponse({ ok: false, error: "refusing to fill on a non-HTTPS page" });
          }
          await ensureConnected();
          if (!client.ready) return sendResponse({ ok: true, filled: false });
          let cred = pwCacheGet(host, msg.loginName?.username);
          if (!cred) {
            cred = await client.getPasswordForLoginName(tab.id, tab.url, msg.loginName);
            if (cred) pwCacheSet(host, cred);
          }
          let filled = false;
          if (cred) {
            // content script re-checks expectedHost before filling
            const resp = await chrome.tabs.sendMessage(tab.id, {
              type: "fill",
              username: cred.username,
              password: cred.password,
              expectedHost: host,
            });
            filled = !!resp?.filled;
            if (filled) {
              recordMru(host, cred.username);
              lastFillByTab.set(tab.id, { host, username: cred.username });
            }
          }
          sendResponse({ ok: true, filled });
          break;
        }

        case "refreshAndRefill": {
          // drop cache then re-fill the tab's last-filled login with a fresh read, so a
          // password changed in the Passwords app lands without re-clicking Fill
          pwCacheClear();
          await ensureConnected();
          if (!client.ready) return sendResponse({ ok: true, refilled: false });
          const tab = await activeTab();
          const entry = tab?.id != null ? lastFillByTab.get(tab.id) : null;
          const host = tab?.url ? registrableHost(tab.url) : null;
          if (!entry || !host || !isSupportedCredentialUrl(tab.url) || entry.host !== host) {
            return sendResponse({ ok: true, refilled: false });
          }
          try {
            const cred = await client.getPasswordForLoginName(tab.id, tab.url, { username: entry.username });
            if (!cred) return sendResponse({ ok: true, refilled: false });
            pwCacheSet(host, cred);
            const resp = await chrome.tabs.sendMessage(tab.id, {
              type: "fill",
              username: cred.username,
              password: cred.password,
              expectedHost: host,
            });
            sendResponse({ ok: true, refilled: !!resp?.filled, username: cred.username });
          } catch (e) {
            sendResponse({ ok: true, refilled: false, error: String(e?.message ?? e) });
          }
          break;
        }

        case "clearCache":
          // popup refresh: drop cached passwords so the next fill re-reads a just-changed one
          pwCacheClear();
          sendResponse({ ok: true });
          break;

        case "disconnect":
          lastHelperActivityAt = 0;
          client.disconnect();
          sendResponse({ ok: true, state: client.state });
          break;

        case "setHelperIdleMinutes": {
          if (!isFromOwnUi(sender)) return sendResponse({ ok: false, error: "forbidden" });
          const minutes = Number(msg.minutes);
          if (!ALLOWED_HELPER_IDLE_MINUTES.has(minutes)) {
            return sendResponse({ ok: false, error: "unsupported idle timeout" });
          }
          helperIdleMinutes = minutes;
          await chrome.storage.local.set({ helperIdleMinutes: minutes });
          scheduleMaintenance();
          sendResponse({ ok: true, minutes });
          break;
        }

        default:
          sendResponse({ ok: false, error: "unknown message" });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message ?? e), state: client.state });
    }
  })().finally(() => {
    activeMessages = Math.max(0, activeMessages - 1);
    if (client.port && lastHelperActivityAt > 0) lastHelperActivityAt = Date.now();
    scheduleMaintenance();
  });
  return true; // async response
});
