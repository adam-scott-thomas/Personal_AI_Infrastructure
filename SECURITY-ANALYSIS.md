# PAI-Install Security Analysis Report

**Date:** 2026-06-04
**Scope:** PAI-Install system across v3.0, v4.0.0, v4.0.1, v4.0.2, v4.0.3, v5.0.0 + Tools/BackupRestore.ts + Tools/validate-protected.ts

---

## Executive Summary

The PAI-Install system demonstrates generally strong security posture for a localhost-only installer: server binding is consistently `127.0.0.1`, Electron configuration disables `nodeIntegration`, and secrets are written with restrictive file permissions. However, several findings warrant attention, ranging from low-severity informational issues to medium-severity concerns around shell injection and path traversal.

**Critical findings: 0** | **High findings: 0** | **Medium findings: 5** | **Low findings: 6** | **Informational: 4**

---

## Finding 1: Shell Command Injection via User-Provided Paths (Medium)

**Affected versions:** v3.0, v4.0.0, v4.0.1, v4.0.2, v4.0.3, v5.0.0
**Files:**
- `Releases/v3.0/.claude/PAI-Install/engine/actions.ts` — lines 343, 361, 371, 576
- `Releases/v4.0.0/.claude/PAI-Install/engine/actions.ts` — lines 343, 361, 371, 577
- `Releases/v5.0.0/.claude/PAI/PAI-Install/engine/actions.ts` — lines 343+, 576+

**Description:**
The `tryExec()` function passes strings directly to `execSync()`, which invokes a shell. User-provided values like `projectsDir` are interpolated into shell commands via string templates without shell-escaping:

```typescript
// actions.ts (all versions)
const pullResult = tryExec(`cd "${paiDir}" && git pull origin main 2>&1`, 60000);
// ...
`git clone https://github.com/danielmiessler/PAI.git "${paiDir}" 2>&1`
```

While `paiDir` is derived from `homedir()` (not user-controlled), the `projectsDir` input goes through only `.trim()` and `replace(/^~/, homedir())` before being stored. The `aliasLine` construction at line 576-577 (v4.0.0) directly interpolates `paiDir`:

```typescript
const aliasLine = `alias pai='bun ${join(paiDir, "skills", "PAI", "Tools", "pai.ts")}'`;
```

This alias is then written to `~/.zshrc`. If `paiDir` could be influenced (e.g., via environment variable `PAI_CONFIG_DIR`), injection into the shell rc file is possible.

**Attack chain:**
1. Attacker controls `PAI_CONFIG_DIR` environment variable or can influence `paiDir`
2. Inject shell metacharacters into the path (e.g., `'; malicious_command; echo '`)
3. Commands execute in `tryExec()` calls or persist in `~/.zshrc` alias

**Mitigating factors:**
- `paiDir` is derived from `homedir()` in most cases, not directly from user input
- `projectsDir` user input only goes into `settings.json` and `mkdirSync`, not directly into `execSync`
- The installer runs locally as the current user

**Recommendation:** Use `execFileSync` with argument arrays instead of `execSync` with shell string interpolation. Validate/sanitize all paths before shell use.

---

## Finding 2: Path Traversal in BackupRestore.ts (Medium)

**Affected file:** `Tools/BackupRestore.ts` — lines 134-174

**Description:**
The `restoreBackup()` function accepts a `backupName` from CLI arguments. While it attempts to constrain names with `BACKUP_PREFIX`, it also accepts absolute paths directly:

```typescript
// BackupRestore.ts, line 136-138
const backupPath = backupName.startsWith("/")
    ? backupName  // Accepts ANY absolute path
    : join(HOME, backupName.startsWith(BACKUP_PREFIX) ? backupName : `${BACKUP_PREFIX}${backupName}`);
```

At line 159, it performs `rmSync(CLAUDE_DIR, { recursive: true, force: true })` before copying from the attacker-controlled path at line 166:

```typescript
rmSync(CLAUDE_DIR, { recursive: true, force: true });
// ...
cpSync(backupPath, CLAUDE_DIR, { recursive: true });
```

**Attack chain:**
1. Attacker provides an absolute path to a malicious directory: `bun BackupRestore.ts restore /tmp/malicious-payload`
2. The script deletes `~/.claude` entirely
3. The malicious directory contents are copied to `~/.claude`, replacing all configuration, skills, and hooks
4. Next time Claude Code runs, it loads attacker-controlled CLAUDE.md, hooks, and skill files

**Mitigating factors:**
- Requires local CLI access (same user context)
- Creates a pre-restore backup before deleting

**Recommendation:** Restrict `backupPath` resolution to only `$HOME/claude-backup-*` directories. Reject absolute paths. Validate the backup directory contains expected PAI structure before restoring.

---

## Finding 3: API Key Exposure Over WebSocket (Medium)

**Affected versions:** v3.0, v4.0.0, v4.0.1, v4.0.2, v4.0.3, v5.0.0
**Files:**
- `Releases/*/...PAI-Install/web/routes.ts` — lines 130-143

**Description:**
API keys entered by users are transmitted as plaintext JSON over the WebSocket connection:

```typescript
// routes.ts, line 130-143 (all versions)
case "user_input": {
    const pending = pendingRequests.get(msg.requestId);
    if (pending) {
        pending.resolve(msg.value);  // Raw key value passed through
        pendingRequests.delete(msg.requestId);
        const display = msg.value.startsWith("sk-") || msg.value.startsWith("xi-")
            ? msg.value.substring(0, 8) + "..."
            : msg.value;
```

The masking logic (line 136) only applies to the *display echo*, not the actual value transmission. The raw key is stored in the WebSocket message history and rebroadcast to any connecting client:

```typescript
// routes.ts, line 117-120
for (const m of messageHistory) {
    ws.send(JSON.stringify({ ...m, replayed: true }));
}
```

**Attack chain:**
1. Attacker on same machine opens a WebSocket to `ws://127.0.0.1:1337/ws`
2. Receives full message history including any plaintext API key echoes
3. While the display is masked, the raw `user_input` messages in history could contain key prefixes

**Mitigating factors:**
- Server bound to `127.0.0.1` — requires local access
- The raw key value itself is only in the `pending.resolve()` path, not directly in broadcast
- The masked display is what gets broadcast, not the raw value
- However, any other WebSocket client receives the 8-char prefix

**Recommendation:** Do not store API-key-related messages in `messageHistory`. Mark key input requests with a `sensitive: true` flag and exclude them from replay.

---

## Finding 4: Symlink to ~/.env Exposes Secrets System-Wide (Medium)

**Affected versions:** v4.0.0, v4.0.1, v4.0.2, v4.0.3, v5.0.0
**Files:**
- `Releases/v4.0.0/.claude/PAI-Install/engine/actions.ts` — lines 551-571
- `Releases/v5.0.0/.claude/PAI/PAI-Install/engine/actions.ts` — similar location

**Description:**
The installer creates symlinks from `~/.env` and `~/.claude/.env` pointing to `~/.config/PAI/.env`:

```typescript
// actions.ts, lines 551-571 (v4.0.0)
const symlinkPaths = [
    join(paiDir, ".env"),         // ~/.claude/.env
    join(homedir(), ".env"),      // ~/.env (voice server reads this)
];
for (const symlinkPath of symlinkPaths) {
    // ...
    symlinkSync(envPath, symlinkPath);
}
```

Creating `~/.env` makes the ElevenLabs API key (and potentially other secrets) visible to any tool that loads `.env` files from the home directory. Many frameworks (Bun, dotenv, etc.) auto-load `~/.env` or walk up directories to find `.env`.

**Attack chain:**
1. Installer creates `~/.env` symlink containing `ELEVENLABS_API_KEY=...`
2. Any application run from `$HOME` that auto-loads `.env` files gains access to the key
3. Unrelated projects running in subdirectories of `$HOME` could inherit the key

**Mitigating factors:**
- The symlink source file has `0o600` permissions
- Only the current user can read it
- The key is for ElevenLabs TTS, not a high-value target

**Recommendation:** Avoid creating `~/.env`. Have the voice server read directly from `~/.config/PAI/.env` instead.

---

## Finding 5: Regex Injection in findExistingEnvKey (Medium)

**Affected versions:** v4.0.0, v4.0.1, v4.0.2, v4.0.3
**Files:**
- `Releases/v4.0.0/.claude/PAI-Install/engine/actions.ts` — line 46

**Description:**
The `findExistingEnvKey` function constructs a regex from the `keyName` parameter:

```typescript
// actions.ts, line 46 (v4.0.0)
const match = content.match(new RegExp(`^${keyName}=(.+)$`, "m"));
```

If `keyName` contains regex metacharacters, this could cause unintended matches or ReDoS. While `keyName` is currently hardcoded to `"ELEVENLABS_API_KEY"`, the function signature accepts any string.

**Mitigating factors:**
- Currently only called with hardcoded key names
- Impact limited to incorrect env key matching

**Recommendation:** Escape `keyName` with a regex-escape function before interpolation.

---

## Finding 6: ElevenLabs API Key Validation Endpoint Difference (Low)

**Affected versions:** v4.0.0 specifically
**Files:**
- `Releases/v4.0.0/.claude/PAI-Install/engine/detect.ts` — line 158

**Description:**
v4.0.0 validates ElevenLabs keys against `/v1/user`:

```typescript
// v4.0.0 detect.ts, line 158
const res = await fetch("https://api.elevenlabs.io/v1/user", {
```

All other versions (v3.0, v4.0.1-v4.0.3, v5.0.0) use `/v1/voices`:

```typescript
// v4.0.3 detect.ts, line 162
const res = await fetch("https://api.elevenlabs.io/v1/voices", {
```

The `/v1/user` endpoint requires `user_read` permission, which many API keys lack. This causes valid keys to be rejected in v4.0.0, creating a usability issue. Later versions (v4.0.1+) also handle 401 with `missing_permissions` as a valid key signal.

**SSRF Assessment:** No SSRF risk — all versions use hardcoded URLs. The API key is sent only as a header value, not embedded in a URL.

**Recommendation:** Already fixed in v4.0.1+. No action needed for current versions.

---

## Finding 7: No WebSocket Authentication (Low)

**Affected versions:** v3.0, v4.0.0, v4.0.1, v4.0.2, v4.0.3, v5.0.0
**Files:**
- `Releases/*/...PAI-Install/web/server.ts` — lines 64-70

**Description:**
The WebSocket endpoint at `/ws` accepts connections without any authentication:

```typescript
// server.ts, lines 64-70 (all versions)
if (url.pathname === "/ws") {
    const upgraded = server.upgrade(req);
    if (!upgraded) {
        return new Response("WebSocket upgrade failed", { status: 400 });
    }
    return undefined as any;
}
```

Any local process can connect, send `start_install`, and drive the installation flow.

**Mitigating factors:**
- Server bound to `127.0.0.1`
- Only local processes can connect
- Installation is a one-time operation

**Recommendation:** Add a random session token generated at server start and require it in WebSocket upgrade requests.

---

## Finding 8: curl | bash Pattern in install.sh (Low)

**Affected versions:** v3.0, v4.0.0, v4.0.1, v4.0.2, v4.0.3
**Files:**
- `Releases/v4.0.0/.claude/PAI-Install/install.sh` — line 122
- `Releases/v4.0.0/.claude/PAI-Install/engine/actions.ts` — line 199

**Description:**
Bun is installed via pipe-to-shell pattern:

```bash
# install.sh, line 122
curl -fsSL https://bun.sh/install | bash 2>/dev/null
```

```typescript
// actions.ts, line 199
const result = tryExec("curl -fsSL https://bun.sh/install | bash", 60000);
```

This is a well-known supply chain risk vector. A MITM or compromised CDN could serve malicious install script.

**Mitigating factors:**
- Uses HTTPS (`-fsSL`)
- bun.sh is a well-maintained official installer
- This is standard practice for Bun installation
- The `-f` flag in curl fails on HTTP errors

**Recommendation:** Consider pinning a checksum or using package managers where available.

---

## Finding 9: validate-protected.ts Exception Bypass Patterns (Low)

**Affected file:** `Tools/validate-protected.ts` — lines 146-169

**Description:**
The validator supports exception files and wildcard exception patterns:

```typescript
// validate-protected.ts, lines 156-165
const isWildcardException = exceptions.some(exc => {
    if (exc.includes('*')) {
        const escapedPattern = exc
            .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '[^/]+');
        return new RegExp(`^${escapedPattern}$`).test(file);
    }
    return false;
});
```

Additionally, the `hasExceptionContext` function (lines 123-133) allows bypassing pattern checks if a line contains certain context prefixes:

```typescript
function hasExceptionContext(line: string, patternCategory: ProtectedPatterns): boolean {
    const allowedPrefixes = patternCategory.exception_contexts?.allowed_prefixes || [];
    for (const prefix of allowedPrefixes) {
        if (line.toLowerCase().includes(prefix.toLowerCase())) {
            return true;
        }
    }
    return false;
}
```

**Bypass patterns:**
1. Add a file to `exception_files` in `.pai-protected.json`
2. Include `allowed_prefixes` text (e.g., "# Example:") on the same line as sensitive content
3. Use wildcard exception patterns that match target files

**Mitigating factors:**
- `.pai-protected.json` is version-controlled; changes are visible in PRs
- This is a development-time tool, not a runtime security control
- Exception mechanism is intentionally designed for legitimate use cases

**Recommendation:** Log exception bypasses prominently. Consider requiring explicit opt-in per pattern category rather than blanket exceptions.

---

## Finding 10: Directory Traversal Prevention via path.join (Low)

**Affected versions:** v3.0, v4.0.0, v4.0.1, v4.0.2, v4.0.3, v5.0.0
**Files:**
- `Releases/*/...PAI-Install/web/server.ts` — lines 73-79

**Description:**
The directory traversal check uses `startsWith`:

```typescript
// server.ts, lines 73-79 (all versions)
let filePath = url.pathname === "/" ? "/index.html" : url.pathname;
const fullPath = join(PUBLIC_DIR, filePath);

if (!fullPath.startsWith(PUBLIC_DIR)) {
    return new Response("Forbidden", { status: 403 });
}
```

`path.join` resolves `..` components, so `join("/public", "../etc/passwd")` becomes `/etc/passwd`, which correctly fails the `startsWith` check. However, this relies on `join` behavior and could be fragile with URL-encoded paths or symlinks within `PUBLIC_DIR`.

**Mitigating factors:**
- `Bun.serve`'s URL parser handles decoding before `url.pathname`
- The check correctly prevents basic traversal
- Server is localhost-only

**Recommendation:** Use `path.resolve` and compare normalized paths. Consider using `realpath` to resolve symlinks.

---

## Finding 11: Detached Voice Server Process (Low)

**Affected versions:** v4.0.0, v4.0.1, v4.0.2, v4.0.3
**Files:**
- `Releases/v4.0.0/.claude/PAI-Install/engine/actions.ts` — lines 723-728

**Description:**
The voice server is spawned as a detached process:

```typescript
const child = spawn("bun", ["run", serverTs], {
    cwd: voiceServerDir,
    detached: true,
    stdio: "ignore",
});
child.unref();
```

The process persists after the installer exits, listening on port 8888 with no authentication. Combined with the `~/.env` symlink, it can serve TTS with the user's API key.

**Mitigating factors:**
- Voice server binds to localhost
- This is intentional design for voice functionality to persist

**Recommendation:** Document the persistent process. Consider adding a simple bearer token for the voice server's HTTP API.

---

## Informational Findings

### I-1: Electron Security Configuration (Good)

All versions with Electron wrappers correctly configure:
- `nodeIntegration: false`
- `contextIsolation: true`
- Single instance lock via `app.requestSingleInstanceLock()`
- Server loads from `127.0.0.1` only

### I-2: API Key File Permissions (Good)

All versions write `.env` files with `mode: 0o600` (owner read/write only).

### I-3: Inactivity Timeout (Good)

All versions implement a 30-minute inactivity timeout that shuts down the installer server.

### I-4: v5.0.0 Consent Gate for Key Scanning (Good)

v5.0.0 adds an explicit "Upfront scan permission gate" before reading potentially sensitive data from old installations, asking user consent before scanning backup directories for API keys.

---

## Version Comparison Matrix

| Security Feature | v3.0 | v4.0.0 | v4.0.1 | v4.0.2 | v4.0.3 | v5.0.0 |
|---|---|---|---|---|---|---|
| Localhost binding | 127.0.0.1 | 127.0.0.1 | 127.0.0.1 | 127.0.0.1 | 127.0.0.1 | 127.0.0.1 |
| ElevenLabs endpoint | /v1/voices | /v1/user | /v1/voices | /v1/voices | /v1/voices | /v1/voices |
| 401 missing_permissions handling | Yes | No | Yes | Yes | Yes | Yes |
| .env permissions 0o600 | Yes | Yes | Yes | Yes | Yes | Yes |
| ~/.env symlink created | No | Yes | Yes | Yes | Yes | Yes |
| WebSocket auth | None | None | None | None | None | None |
| Electron nodeIntegration | false | false | false | false | false | false |
| Electron contextIsolation | true | true | true | true | true | true |
| Consent gate for key scanning | No | No | No | No | No | Yes |
| install.sh present | Yes | Yes | Yes | Yes | Yes | No |
| Pulse/VoiceServer mgmt | VoiceServer | VoiceServer | VoiceServer | VoiceServer | VoiceServer | Pulse |

---

## Recommendations Priority

1. **[Medium]** Replace `execSync` string interpolation with `execFileSync` + argument arrays in all `actions.ts` files
2. **[Medium]** Restrict `BackupRestore.ts` path resolution to `$HOME/claude-backup-*` only
3. **[Medium]** Don't persist API key messages in WebSocket replay history
4. **[Medium]** Remove `~/.env` symlink; configure voice server to read from `~/.config/PAI/.env` directly
5. **[Medium]** Escape regex metacharacters in `findExistingEnvKey`
6. **[Low]** Add session token to WebSocket authentication
7. **[Low]** Pin checksum for Bun installer script
