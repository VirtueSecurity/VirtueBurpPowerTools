# Virtue Burp Power Tools

Virtue Burp Power Tools is a Burp Suite extension (Montoya API) by [Nick Coblentz](https://github.com/ncoblentz/) from [Virtue Security](https://www.virtuesecurity.com). It bundles a set of utilities used during penetration tests to speed up common workflows, probe for issues at scale, manage sessions, work with WebSockets, and extract/share evidence.

This README reflects the current features of the extension and provides quick usage guidance.

## Features Overview

- Copy Request/Response (context menu + hotkey)
- Retry Requests (HTTP) and Verb Fuzzing (+ clipboard URL runner)
- WebSocket Utilities (show upgrade request, WS "Intruder"-style integers, connection helpers)
- Auto‑Name Repeater Tabs; Organizer helpers; Scope include/exclude
- Session Access Token Helper (passive capture + session handling action)
- Match/Replace Session Action (regex-based request rewriting)
- Every Parameter (bulk payload injection across headers/params/path; minimizer; auth tests; DOH; IP spoof headers, etc.)
- Manual Scan Issue Manager (log grouped manual issues with labels)
- Passive Scan Check: Disposable Email Disclosure
- Apply Anomaly Rank (context action for ranking)

Details for each feature are below.

---

## Installation

### Build

Clone the repo and build the shaded JAR:

- Linux/macOS: `./gradlew shadowJar`
- Windows: `gradlew.bat shadowJar`

The output will be in `build/libs/VirtueBurpPowerTools-x.y.z-all.jar`.

### Load in Burp

1. Open Burp Suite
2. Go to the Extensions tab
3. Add > Extension type: Java
4. Select the JAR from `build/libs`

The extension name appears as `Virtue Security Unified Burp Extension`.

---

## Copy Request/Response
Source: `com.nickcoblentz.montoya.utils.CopyRequestResponse`

- Right‑click any HTTP message(s) or within the HTTP message editor to copy content in various formats (full request+response, headers only, URL+response, etc.).
- Hotkey: `Ctrl+Shift+C` copies full Request + Response when focused in the HTTP editor.

Tip: This is designed to paste cleanly into Markdown reports.

---

## Retry Requests and HTTP Verb Fuzzing
Source: `com.nickcoblentz.montoya.utilities.retry.*`

Right‑click menu under the “Retry” group provides:

- Retry Requests: Re‑send selected requests; view results in Logger.
- Retry Verbs: For each selected URL, try common and uncommon HTTP methods.
  - Variants include recalculating `Content-Length` and JSON variants when appropriate.
- Request URLs from Clipboard: If you have one‑per‑line URLs on your clipboard, the menu will appear and can send them immediately as requests.
- List Open WS Connections: Quick diagnostic listing in the output.

Hotkey: `Ctrl+Shift+E` to retry selected requests.

Settings:
- Limit concurrent HTTP requests and set a numeric limit.

---

## WebSocket Utilities (WS Utils)
Source: `com.nickcoblentz.montoya.websocket.MontoyaWSUtils`

Context menu (when a WS message or editor is selected) under “WS Utils”:

- Show Upgrade Request: Opens a read‑only HTTP editor showing the original Upgrade request that established the WS connection.
- Intruder: Integers: Opens a small UI that:
  - Lets you select a live WS connection
  - Choose a start/end integer range
  - Provide a token to replace (e.g., `REPLACEME`)
  - Sends websocket messages with the token replaced by each integer in range, honoring a configurable concurrency limit.

Behavior/Settings:
- Tracks active proxy WS connections automatically.
- Setting: “Limit the number of WebSocket messages sent at one time to” (default 25).
- Setting: “Automatically Reconnect to Next WS Connection Matching Upgrade Request” (bump to newest connection on close).

---

## Identify Unique Requests/Responses with Anomaly Rank
Source: `KotlinBurpAutoNameRepeaterTabExtension`

Context menu under “AutoName”:

- Send To Repeater & Auto Name: Creates a Repeater tab with a sensible, stable name derived from the method and normalized path (replaces UUIDs, version prefixes, numeric segments).
- Send Unique Host/Path To Organizer
- Send Unique Verb/Host/Path To Organizer
- Send Unique Verb/URL To Organizer
  - For each grouping, items are ranked and deduplicated by rank before sending to Organizer; annotations can include test case notes when present.
- Add Base URL to Scope / Exclude Base URL from Scope

Optional Settings (see “Settings” below) support customizing Organizer notes/highlighting.

---

## Session Access Token Helper
Source: `MontoyaKotlinSessionAccessTokenHelper`

Two complementary modes:

1) Passive capture
- When enabled, responses across tools are inspected for an access token pattern (default regex matches a JSON `"access_token"` value). When found, the token is cached.
- Subsequent requests get configured headers injected (e.g., `Authorization: Bearer <token>` and an optional second header) unless URL matches your “ignore endpoints” regex.

2) Session Handling Action
- Add a Burp Session Handling Rule: Invoke this extension (“Session Handling: Access Token Helper”).
- The action will:
  - Extract the token from macro responses when a login macro runs
  - Apply headers to the current request

Context Menu:
- “Session Access Token > Test It” previews how the current/selected request would be modified.

Key Settings:
- Token regex pattern (default matches `"access_token" : "..."`)
- Header name/value prefix/suffix for up to two headers
- Passive capture toggle
- Ignore Endpoints (regex) and enable/disable toggle

---

## Match/Replace Session Action
Source: `MatchReplaceSessionExtension`

- A Session Handling Action that applies up to three regex “match/replace” operations to the raw HTTP request text.
- Context menu includes “Replace Session > Test It” to preview replacements against selected/current request(s).

Settings:
- Three pairs of Match/Replace regexes, applied in order with case‑insensitive, dot‑matches‑all, multiline flags.

---

## Every Parameter
Source: `com.nickcoblentz.montoya.EveryParameter`

Bulk testing helpers (context menu “Every”) that iterate through headers, parameters, JSON/XML, path slices, and cookies to inject payloads, with results sent to Logger (and option to send to Repeater/Comparer in some flows):

Included actions (highlights):
- SQLi: sleep polyglot, logic, concat, comment, error payloads
- XSS: standard payloads, UTF‑7 style, blind XSS image, Markdown image
- XML: external entity OOB/file payloads (prepend/replace, with encoding variants)
- Collaborator: URL and email payloads; Log4J JNDI payloads
- URL Path Special Chars: inject a battery of path characters and encodings at multiple indices
- Headers: inject/replace across all headers; also test `Authorization: Basic <b64>` with payload
- Authorization Tests: a curated set of bypass attempts, including path tampering (`..`, encoding variants, static path prefixes), capitalization changes, and headers like `X-Original-Url`/`X-Rewrite-Url`
- Spoof IP Using Headers: tries many common proxy/IP headers (and `Host`) with local/LAN/IP/Collaborator values and the server’s resolved IP
- DNS‑over‑HTTP: sample GET/POST queries using common DOH endpoints and content types
- Max‑Forwards: sends TRACE/GET/HEAD with varying `Max-Forwards`
- Minimize: automatically tries to remove/empty headers and parameters while keeping the response “similar,” then sends the minimized version to Repeater and the diff to Comparer

Settings:
- Ignore Parameters (regex) to skip sensitive/volatile names
- Follow Redirects toggle when sending test requests

Notes:
- Test cases are labeled with headers (`Z-Test-Case-*`) so they can be surfaced via Bambda custom columns in Logger.

---

## Manual Scan Issue Manager
Source: `com.nickcoblentz.montoya.ManualScanIssueManager`

- Context menu “Manual Issue > Log Manual Scan Issue” opens a dialog to create/update a grouped manual issue.
- Choose an Issue Category (role/tenant/context authorization, XSS, SQLi, Anonymous Access, Other) and either create a new label or add to an existing label.
- The extension persists label lists per project and updates/creates an issue accordingly with Burp Scanner APIs.

---

## Passive Scan Check: Disposable Email Disclosure
Source: `com.nickcoblentz.montoya.DisposableEmailScanChecker`

- A passive scan check that loads the public disposable email blocklist and flags any responses disclosing addresses from those domains.
- Issues are raised with details and the observed addresses/domains.

Note: The list is fetched at startup using a standard HTTP client; failures are logged to the Burp output.

---

## Apply Anomaly Rank
Source: `ApplyAnomalyRank.kt`

- Registers a context menu item that applies anomaly ranking utilities on selected items (visible in context menus). Useful to sort/deduplicate when sending to Organizer/Repeater.

---

## Settings Reference
All settings are exposed under a single “Virtue Unified Burp Extension” settings panel (Project settings). Highlights:

- Retry Requests
  - Limit concurrent HTTP requests (boolean)
  - Concurrent HTTP Request Limit (int)
- Auto Name Repeater
  - Use page title in Organizer notes (bool)
  - Tag groups in Organizer notes (bool)
  - Prepend/Append strings for Organizer notes (string)
  - Highlight color when sending to Organizer (enum)
- Session Match/Replace
  - Three Match/Replace regex pairs
- Every Parameter
  - Ignore Parameters (regex)
  - Follow Redirects (bool)
- Session Access Token Helper
  - Access Token regex pattern
  - Header1/2 name and value prefix/suffix
  - Ignore Endpoints (regex) and toggle
  - Passive capture toggle
- WS Utils
  - Concurrency limit (int)
  - Auto‑bump to next WS connection on close (bool)

---

## Hotkeys

- Copy Full Request/Response: `Ctrl+Shift+C`
- Retry Requests: `Ctrl+Shift+E`

(Hotkeys apply when focus is appropriate within Burp’s UI.)

---
