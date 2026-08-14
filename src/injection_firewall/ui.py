"""Self-contained browser UI assets for the local upload API."""

PAGE = """<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Document Injection Firewall</title>
  <link rel="stylesheet" href="/assets/firewall.css">
  <script src="/assets/firewall.js" defer></script>
</head>
<body>
  <main class="shell">
    <header class="masthead">
      <div class="brand-mark" aria-hidden="true">DIF</div>
      <div>
        <p class="eyebrow">LOCAL · DETERMINISTIC · FAIL-CLOSED</p>
        <h1>Document Injection Firewall</h1>
        <p class="lede">AI가 파일을 읽기 전에 숨겨진 명령과 구조적 이상을 먼저 검사합니다.</p>
      </div>
    </header>

    <section class="panel upload-panel" aria-labelledby="upload-title">
      <div class="section-heading">
        <div>
          <p class="step">01 · 파일 선택</p>
          <h2 id="upload-title">검사할 문서를 올려주세요</h2>
        </div>
        <span class="local-badge">로컬 API</span>
      </div>

      <form id="scan-form">
        <label class="drop-zone" id="drop-zone" for="file-input">
          <span class="upload-icon" aria-hidden="true">↑</span>
          <strong>파일을 끌어 놓거나 클릭해서 선택</strong>
          <span>최대 50 MB · 한 번에 한 파일</span>
          <input id="file-input" name="file" type="file" required
            accept=".txt,.md,.markdown,.html,.htm,.docx,.pptx,.xlsx,.pdf,.png,.jpg,.jpeg">
        </label>

        <div class="file-row" id="file-row" hidden>
          <div class="file-copy">
            <strong id="file-name"></strong>
            <span id="file-size"></span>
          </div>
          <button class="text-button" id="remove-file" type="button">선택 해제</button>
        </div>

        <p class="formats">TXT · Markdown · HTML · DOCX · PPTX · XLSX · PDF · PNG · JPEG</p>
        <button class="primary-button" id="scan-button" type="submit" disabled>격리 검사 시작</button>
      </form>

      <div class="progress" id="progress" role="status" aria-live="polite" hidden>
        <span class="spinner" aria-hidden="true"></span>
        <div>
          <strong id="progress-title">파일을 격리 영역으로 전송하는 중</strong>
          <span id="progress-detail">문서 내용은 신뢰할 수 없는 데이터로 처리됩니다.</span>
        </div>
      </div>

      <div class="error-box" id="error-box" role="alert" hidden></div>
    </section>

    <section class="panel result-panel" id="result-panel" aria-labelledby="result-title" hidden>
      <div class="section-heading">
        <div>
          <p class="step">02 · 검사 결과</p>
          <h2 id="result-title">판정이 완료되었습니다</h2>
        </div>
        <span class="risk-badge" id="risk-badge"></span>
      </div>

      <div class="verdict" id="verdict">
        <strong id="verdict-title"></strong>
        <p id="verdict-copy"></p>
      </div>

      <div class="result-grid">
        <article>
          <h3>탐지 근거</h3>
          <ul id="evidence-list"></ul>
        </article>
        <article>
          <h3>탐지 위치</h3>
          <ul id="location-list"></ul>
        </article>
        <article>
          <h3>구조적 이상</h3>
          <ul id="anomaly-list"></ul>
        </article>
      </div>

      <div class="result-footer">
        <p>작업 ID <code id="job-id"></code></p>
        <div class="actions">
          <a class="secondary-button" id="derivative-link" hidden>표시된 파생본 다운로드</a>
          <button class="primary-button compact" id="scan-another" type="button">다른 파일 검사</button>
        </div>
      </div>
    </section>

    <aside class="trust-note">
      <strong>중요:</strong> 낮은 위험 판정도 문서 내용을 신뢰 가능한 명령으로 바꾸지 않습니다.
      이후 단계에서도 파일 내용은 오직 데이터로만 취급해야 합니다.
    </aside>
  </main>
</body>
</html>
"""


STYLES = """
:root {
  --ink: #13231e;
  --muted: #62716b;
  --line: #d8e1dd;
  --paper: #fbfcfa;
  --white: #ffffff;
  --green: #146b4a;
  --green-dark: #0d5138;
  --green-soft: #e8f4ee;
  --amber: #8a5600;
  --amber-soft: #fff4d8;
  --red: #a52b30;
  --red-soft: #fdebed;
  --shadow: 0 18px 55px rgba(29, 54, 45, 0.09);
  font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--ink);
  background: #eef3f0;
}

* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; background: radial-gradient(circle at 10% 0%, #fff 0, transparent 32%), #eef3f0; }
button, input { font: inherit; }
button, a { -webkit-tap-highlight-color: transparent; }

.shell { width: min(920px, calc(100% - 32px)); margin: 0 auto; padding: 54px 0 48px; }
.masthead { display: flex; gap: 22px; align-items: flex-start; margin-bottom: 28px; }
.brand-mark { display: grid; place-items: center; width: 58px; height: 58px; flex: 0 0 auto; border-radius: 15px; background: var(--ink); color: #fff; font-size: 15px; font-weight: 800; letter-spacing: .08em; box-shadow: 0 10px 24px rgba(19, 35, 30, .2); }
.eyebrow, .step { margin: 0 0 7px; color: var(--green); font-size: 12px; line-height: 1.3; font-weight: 800; letter-spacing: .13em; }
h1 { margin: 0; font-size: clamp(28px, 5vw, 42px); line-height: 1.08; letter-spacing: -.04em; }
.lede { margin: 10px 0 0; color: var(--muted); font-size: 16px; line-height: 1.6; }

.panel { border: 1px solid rgba(19, 35, 30, .09); border-radius: 22px; background: var(--white); box-shadow: var(--shadow); padding: clamp(22px, 5vw, 36px); }
.section-heading { display: flex; justify-content: space-between; gap: 18px; align-items: flex-start; margin-bottom: 24px; }
h2 { margin: 0; font-size: 23px; letter-spacing: -.025em; }
.local-badge, .risk-badge { display: inline-flex; align-items: center; min-height: 30px; border-radius: 999px; padding: 6px 11px; background: var(--green-soft); color: var(--green-dark); font-size: 12px; font-weight: 800; white-space: nowrap; }

.drop-zone { display: grid; place-items: center; min-height: 230px; border: 1.5px dashed #a9bbb3; border-radius: 17px; background: var(--paper); text-align: center; cursor: pointer; transition: .18s ease; }
.drop-zone:hover, .drop-zone.dragging { border-color: var(--green); background: var(--green-soft); transform: translateY(-1px); }
.drop-zone:focus-within { outline: 3px solid rgba(20, 107, 74, .2); outline-offset: 2px; }
.drop-zone strong { margin: 14px 12px 5px; font-size: 17px; }
.drop-zone span:last-of-type { color: var(--muted); font-size: 13px; }
.upload-icon { display: grid; place-items: center; width: 48px; height: 48px; border-radius: 50%; background: var(--green); color: #fff; font-size: 25px; font-weight: 400; }
#file-input { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.formats { margin: 14px 0 22px; color: var(--muted); text-align: center; font-size: 11px; font-weight: 700; letter-spacing: .06em; }

.file-row { align-items: center; justify-content: space-between; gap: 16px; margin-top: 14px; padding: 13px 15px; border: 1px solid var(--line); border-radius: 12px; }
.file-row:not([hidden]) { display: flex; }
.file-copy { display: flex; flex-direction: column; min-width: 0; }
.file-copy strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-copy span { margin-top: 3px; color: var(--muted); font-size: 12px; }
.text-button { border: 0; background: transparent; color: var(--red); cursor: pointer; font-size: 13px; font-weight: 700; }

.primary-button, .secondary-button { display: inline-flex; justify-content: center; align-items: center; min-height: 48px; border: 0; border-radius: 12px; padding: 0 20px; text-decoration: none; cursor: pointer; font-weight: 800; transition: .15s ease; }
.primary-button { width: 100%; background: var(--green); color: #fff; box-shadow: 0 8px 18px rgba(20, 107, 74, .17); }
.primary-button:hover:not(:disabled) { background: var(--green-dark); transform: translateY(-1px); }
.primary-button:disabled { background: #b7c4be; box-shadow: none; cursor: not-allowed; }
.primary-button.compact { width: auto; min-height: 42px; }
.secondary-button { min-height: 42px; border: 1px solid var(--green); color: var(--green); background: #fff; }

.progress { align-items: center; gap: 14px; margin-top: 18px; padding: 16px; border-radius: 13px; background: var(--green-soft); }
.progress:not([hidden]) { display: flex; }
.progress div { display: flex; flex-direction: column; gap: 3px; }
.progress span { color: var(--muted); font-size: 12px; }
.spinner { width: 22px; height: 22px; border: 3px solid #b5d6c7; border-top-color: var(--green); border-radius: 50%; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.error-box { margin-top: 16px; border-radius: 12px; padding: 14px 16px; background: var(--red-soft); color: var(--red); font-size: 14px; font-weight: 700; }

.result-panel { margin-top: 22px; }
.risk-badge[data-risk="low"] { background: var(--green-soft); color: var(--green-dark); }
.risk-badge[data-risk="review"] { background: var(--amber-soft); color: var(--amber); }
.risk-badge[data-risk="quarantine"] { background: var(--red-soft); color: var(--red); }
.verdict { margin-bottom: 22px; border-left: 4px solid var(--green); border-radius: 0 12px 12px 0; padding: 14px 17px; background: var(--green-soft); }
.verdict[data-risk="review"] { border-color: var(--amber); background: var(--amber-soft); }
.verdict[data-risk="quarantine"] { border-color: var(--red); background: var(--red-soft); }
.verdict p { margin: 5px 0 0; color: #42524c; font-size: 14px; line-height: 1.55; }
.result-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.result-grid article { min-width: 0; border: 1px solid var(--line); border-radius: 14px; padding: 16px; }
.result-grid h3 { margin: 0 0 11px; font-size: 13px; }
.result-grid ul { margin: 0; padding: 0; list-style: none; }
.result-grid li { overflow-wrap: anywhere; margin-top: 7px; border-radius: 8px; padding: 7px 9px; background: var(--paper); color: #415049; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; line-height: 1.45; }
.result-grid li:first-child { margin-top: 0; }
.result-grid li.empty { color: #819089; font-family: inherit; }
.result-footer { display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-top: 22px; padding-top: 19px; border-top: 1px solid var(--line); }
.result-footer p { margin: 0; color: var(--muted); font-size: 12px; }
.result-footer code { color: var(--ink); }
.actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 9px; }
.trust-note { margin: 20px auto 0; max-width: 760px; color: var(--muted); text-align: center; font-size: 13px; line-height: 1.6; }

[hidden] { display: none !important; }
button:focus-visible, a:focus-visible, label:focus-visible { outline: 3px solid rgba(20, 107, 74, .28); outline-offset: 2px; }
@media (max-width: 700px) {
  .shell { padding-top: 28px; }
  .masthead { gap: 14px; }
  .brand-mark { width: 46px; height: 46px; border-radius: 12px; }
  .result-grid { grid-template-columns: 1fr; }
  .result-footer { align-items: stretch; flex-direction: column; }
  .actions { justify-content: stretch; }
  .actions > * { flex: 1 1 auto; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { scroll-behavior: auto !important; animation-duration: .01ms !important; transition-duration: .01ms !important; }
}
"""


SCRIPT = r"""
"use strict";

const MAX_BYTES = 50 * 1024 * 1024;
const ALLOWED_SUFFIXES = new Set([
  ".txt", ".md", ".markdown", ".html", ".htm", ".docx",
  ".pptx", ".xlsx", ".pdf", ".png", ".jpg", ".jpeg"
]);

const form = document.querySelector("#scan-form");
const input = document.querySelector("#file-input");
const dropZone = document.querySelector("#drop-zone");
const fileRow = document.querySelector("#file-row");
const fileName = document.querySelector("#file-name");
const fileSize = document.querySelector("#file-size");
const removeFile = document.querySelector("#remove-file");
const scanButton = document.querySelector("#scan-button");
const progress = document.querySelector("#progress");
const progressTitle = document.querySelector("#progress-title");
const progressDetail = document.querySelector("#progress-detail");
const errorBox = document.querySelector("#error-box");
const resultPanel = document.querySelector("#result-panel");
const riskBadge = document.querySelector("#risk-badge");
const verdict = document.querySelector("#verdict");
const verdictTitle = document.querySelector("#verdict-title");
const verdictCopy = document.querySelector("#verdict-copy");
const derivativeLink = document.querySelector("#derivative-link");
const scanAnother = document.querySelector("#scan-another");

let selectedFile = null;

const verdicts = {
  low: {
    badge: "LOW · 낮은 위험",
    title: "명확한 공격 신호가 발견되지 않았습니다.",
    copy: "안전 또는 신뢰 판정은 아닙니다. 파생본에도 비신뢰 데이터 표시가 유지됩니다."
  },
  review: {
    badge: "REVIEW · 검토 필요",
    title: "자동 통과시키기 애매한 신호가 발견되었습니다.",
    copy: "문서를 AI에 전달하지 말고 격리 상태에서 사용자가 직접 검토하세요."
  },
  quarantine: {
    badge: "QUARANTINE · 격리",
    title: "숨겨진 명령 또는 위험한 구조가 발견되었습니다.",
    copy: "문서와 추출 내용을 후속 AI 입력으로 전달하지 마세요. 파생본도 제공되지 않습니다."
  }
};

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function suffixOf(name) {
  const dot = name.lastIndexOf(".");
  return dot < 0 ? "" : name.slice(dot).toLowerCase();
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function clearError() {
  errorBox.textContent = "";
  errorBox.hidden = true;
}

function selectFile(file) {
  clearError();
  resultPanel.hidden = true;
  selectedFile = null;
  scanButton.disabled = true;
  fileRow.hidden = true;

  if (!file) return;
  if (!ALLOWED_SUFFIXES.has(suffixOf(file.name))) {
    showError("지원하지 않는 파일 형식입니다. 아래 지원 형식 목록을 확인해 주세요.");
    return;
  }
  if (file.size < 1 || file.size > MAX_BYTES) {
    showError("파일은 비어 있지 않아야 하며 크기는 50 MB 이하여야 합니다.");
    return;
  }

  selectedFile = file;
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);
  fileRow.hidden = false;
  scanButton.disabled = false;
}

function renderList(selector, values) {
  const list = document.querySelector(selector);
  list.replaceChildren();
  if (!Array.isArray(values) || values.length === 0) {
    const item = document.createElement("li");
    item.className = "empty";
    item.textContent = "발견되지 않음";
    list.append(item);
    return;
  }
  for (const value of values) {
    const item = document.createElement("li");
    item.textContent = String(value);
    list.append(item);
  }
}

function renderResult(jobId, result) {
  const risk = Object.hasOwn(verdicts, result.risk_level) ? result.risk_level : "quarantine";
  const copy = verdicts[risk];
  riskBadge.dataset.risk = risk;
  riskBadge.textContent = copy.badge;
  verdict.dataset.risk = risk;
  verdictTitle.textContent = copy.title;
  verdictCopy.textContent = copy.copy;
  document.querySelector("#job-id").textContent = jobId;
  renderList("#evidence-list", result.evidence);
  renderList("#location-list", result.location);
  renderList("#anomaly-list", result.structural_anomalies);

  if (risk === "low") {
    derivativeLink.href = `/v1/scans/${encodeURIComponent(jobId)}/derivative`;
    derivativeLink.download = "untrusted-derivative.txt";
    derivativeLink.hidden = false;
  } else {
    derivativeLink.removeAttribute("href");
    derivativeLink.hidden = true;
  }
  resultPanel.hidden = false;
  resultPanel.scrollIntoView({behavior: "smooth", block: "start"});
}

function delay(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function waitForResult(jobId) {
  for (let attempt = 0; attempt < 360; attempt += 1) {
    const response = await fetch(`/v1/scans/${encodeURIComponent(jobId)}`, {
      headers: {Accept: "application/json"}, cache: "no-store"
    });
    if (!response.ok) throw new Error("status lookup failed");
    const state = await response.json();
    progressTitle.textContent = state.status === "processing" ? "격리 환경에서 분석하는 중" : "검사 작업을 기다리는 중";
    progressDetail.textContent = `작업 ID ${jobId}`;
    if (state.status === "complete") {
      const resultResponse = await fetch(`/v1/scans/${encodeURIComponent(jobId)}/result`, {
        headers: {Accept: "application/json"}, cache: "no-store"
      });
      if (!resultResponse.ok) throw new Error("result lookup failed");
      return resultResponse.json();
    }
    await delay(750);
  }
  throw new Error("scan timeout");
}

input.addEventListener("change", () => selectFile(input.files[0]));
removeFile.addEventListener("click", () => {
  input.value = "";
  selectFile(null);
});

for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  });
}
dropZone.addEventListener("drop", (event) => {
  const files = event.dataTransfer.files;
  if (files.length !== 1) {
    selectFile(null);
    showError("한 번에 한 파일만 선택할 수 있습니다.");
    return;
  }
  selectFile(files[0]);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!selectedFile) return;
  clearError();
  scanButton.disabled = true;
  progress.hidden = false;
  progressTitle.textContent = "파일을 격리 영역으로 전송하는 중";
  progressDetail.textContent = "문서 내용은 신뢰할 수 없는 데이터로 처리됩니다.";
  resultPanel.hidden = true;

  try {
    const body = new FormData();
    body.append("file", selectedFile, selectedFile.name);
    const response = await fetch("/v1/scans", {
      method: "POST", body, headers: {Accept: "application/json"}
    });
    if (!response.ok) throw new Error("upload failed");
    const job = await response.json();
    const result = await waitForResult(job.job_id);
    renderResult(job.job_id, result);
  } catch (_error) {
    showError("검사를 완료하지 못했습니다. 서버 상태와 파일 형식을 확인한 뒤 다시 시도해 주세요.");
  } finally {
    progress.hidden = true;
    scanButton.disabled = selectedFile === null;
  }
});

scanAnother.addEventListener("click", () => {
  input.value = "";
  selectFile(null);
  window.scrollTo({top: 0, behavior: "smooth"});
});
"""
