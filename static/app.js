const screens = [
  document.querySelector("#screen-select"),
  document.querySelector("#screen-compare"),
  document.querySelector("#screen-config"),
  document.querySelector("#screen-dummy"),
  document.querySelector("#screen-approve")
];
const alertBox = document.querySelector("#alert");
const busy = document.querySelector("#busy");
const busyText = document.querySelector("#busy-text");
let sessionId = null;
let state = null;
let currentStep = 0;
let activeConfig = 0;

function isSvnTarget(value) {
  return /^(https?|svn|svn\+ssh|file):\/\//i.test(value.trim());
}

function updateTargetMode() {
  const isRemote = isSvnTarget(document.querySelector("#target-url").value);
  const credentials = document.querySelector("#svn-credentials");
  credentials.hidden = !isRemote;
  document.querySelector("#svn-username").required = isRemote;
  document.querySelector("#svn-password").required = isRemote;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function showAlert(message, kind = "error") {
  alertBox.textContent = message;
  alertBox.className = `alert ${kind}`;
  alertBox.classList.remove("hidden");
}

function clearAlert() {
  alertBox.className = "alert hidden";
  alertBox.textContent = "";
}

function setBusy(enabled, message = "Reviewing your code drop…") {
  busyText.textContent = message;
  busy.classList.toggle("hidden", !enabled);
  document.querySelector("#start-button").disabled = enabled;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status}).`);
  return payload;
}

function api(path) {
  return `/api/sessions/${encodeURIComponent(sessionId)}${path}`;
}

function setStep(step) {
  const ready = Boolean(state);
  currentStep = step;
  document.body.classList.toggle("has-review", ready);
  screens.forEach((screen, index) => screen.classList.toggle("hidden", index !== step));
  document.querySelectorAll(".step-link").forEach((button, index) => {
    button.classList.toggle("active", index === step);
    button.classList.toggle("done", index < step && ready);
    button.disabled = index > 0 && !ready;
  });
  if (step === 1) renderCompare();
  if (step === 2) renderConfig();
  if (step === 3) renderDummy();
  if (step === 4) renderApprove();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function statusPill(text) {
  const kind = /blocker|failed|invalid/i.test(text) ? "blocker" :
    /warning|downgrade|same version/i.test(text) ? "warning" :
      /new|changed|removed|moved/i.test(text) ? "" : "neutral";
  return `<span class="status ${kind}">${escapeHtml(text)}</span>`;
}

function findingContext(finding) {
  const baseline = finding.baseline_file_exists
    ? `<code>${escapeHtml(finding.baseline_file)}</code>`
    : finding.baseline_code_drop
      ? `No matching file in <code>${escapeHtml(finding.baseline_code_drop)}</code> (expected <code>${escapeHtml(finding.baseline_file)}</code>)`
      : "No component baseline available";
  return `<li>Issue in release: <code>${escapeHtml(finding.release)}</code></li>
    <li>Current file: <code>${escapeHtml(finding.current_file)}</code></li>
    <li>Baseline file for config comparison: ${baseline}</li>`;
}

function navButtons() {
  return `<div class="footer-actions">
    <button class="button button-secondary" data-go="${Math.max(0, currentStep - 1)}">← Back</button>
    <button class="button button-primary" data-go="${Math.min(4, currentStep + 1)}">Continue <span>→</span></button>
  </div>`;
}

function skipAreaButton(area) {
  const confirmed = (state?.skipped_areas || []).includes(area);
  return confirmed
    ? `<span class="status">Skip confirmed</span>`
    : `<button class="button button-secondary" data-skip-area="${area}">Confirm skip ${area}</button>`;
}

function renderSelectResults() {
  const host = document.querySelector("#select-results");
  if (!state) {
    host.innerHTML = "";
    return;
  }
  const validation = state.validation || { checked: 0, valid: 0, failed: 0, errors: [] };
  const checks = state.structure_checks || [];
  const isBlocked = validation.failed > 0;
  const missingAreas = state.areas_missing || [];
  const pendingSkips = missingAreas.filter(area => !(state.skipped_areas || []).includes(area));
  const baselineRows = Object.entries(state.baselines || {}).map(([path, baseline]) => {
    const options = state.baseline_options?.[path] || [];
    const selector = options.length > 1
      ? `<select class="baseline-choice" data-path="${escapeHtml(path)}">${options.map(option =>
        `<option value="${escapeHtml(option.code_drop)}" ${option.code_drop === baseline.code_drop ? "selected" : ""}>${escapeHtml(option.code_drop)} · ${state.target_type === "local_folder" ? "local" : `r${escapeHtml(option.revision || "N/A")}`}</option>`
      ).join("")}</select>`
      : escapeHtml(baseline.code_drop);
    const revision = state.target_type === "local_folder"
      ? "Local folder"
      : baseline.revision ? `r${escapeHtml(baseline.revision)}` : "N/A";
    return `<tr><td>${escapeHtml(path.split("/")[1])}</td><td>${escapeHtml(path.split("/")[0])}</td><td>${selector}</td><td>${revision}</td></tr>`;
  }).join("");
  const missingBaselineRows = Object.entries(state.baseline_options || {})
    .filter(([path]) => !state.baselines?.[path])
    .map(([path]) => `<tr><td>${escapeHtml(path.split("/")[1])}</td><td>${escapeHtml(path.split("/")[0])}</td><td colspan="2">New component · no earlier baseline</td></tr>`).join("");
  const releaseCoverageRows = (state.release_coverage || []).map(item =>
    `<tr><td>${escapeHtml(item.code_drop)}</td><td>${escapeHtml(item.component)}</td><td>${statusPill(item.comparison)}</td><td>${escapeHtml(item.details)}</td></tr>`
  ).join("");
  const currentErrorRows = (validation.errors || []).map(error =>
    `<tr><td>${escapeHtml(`${state.folder_name}/Configs/${error.file}`)}</td><td>${error.line}</td><td>${error.column}</td><td>${escapeHtml(error.message)}<pre>${escapeHtml(error.context)}</pre></td></tr>`
  ).join("");
  const baselineErrorRows = (state.baseline_validation_errors || []).map(error =>
    `<tr><td>${escapeHtml(error.source_file)}</td><td>${error.line}</td><td>${error.column}</td><td>${escapeHtml(error.message)}</td></tr>`
  ).join("");
  const errorRows = currentErrorRows + baselineErrorRows;
  const validationErrorCount = (validation.errors || []).length
    + (state.baseline_validation_errors || []).length;
  const duplicateRows = (validation.duplicates || []).map(item =>
    `<tr><td>${escapeHtml(item.file)}</td><td>${escapeHtml(item.key_path)}</td><td colspan="2">Duplicate JSON key (review this warning)</td></tr>`
  ).join("");
  host.innerHTML = `
    <ul class="point-list review-overview">
      <li>${Object.keys(state.baselines || {}).length} component baseline(s) resolved from earlier code drops.</li>
      <li>${validation.checked} JSON file(s) checked; ${validation.failed} invalid.</li>
      <li>${state.historical_comparison_rows || 0} file comparison(s) included across discovered releases.</li>
    </ul>
    ${state.target_type === "local_folder" ? `<div class="banner warning">Offline comparison using the local folder. No remote SVN access or commit is performed.</div>` : ""}
    ${isBlocked ? `<div class="banner error"><strong>Dummy scan blocked.</strong> ${validation.failed} JSON file(s) are invalid. Binary comparisons and reports are available; open the validation details below.</div>` :
      !state.configs_present ? `<div class="banner warning"><strong>Config review is unavailable.</strong> No Configs folder was uploaded, so JSON validation and dummy scanning did not run. This is skipped, not a clean scan.</div>` :
        `<div class="banner">JSON validation passed. The detailed workbooks include all discovered earlier releases and gaps in the preceding five drops.</div>`}
    ${missingAreas.length ? `<div class="missing-review-list">${missingAreas.map(area => `<section class="missing-review-item">
      <div><strong>No ${escapeHtml(area)} folder was found in this ZIP.</strong>
        <ul class="point-list"><li>${area === "Binaries" ? "File and version comparison for this release cannot run." : "Config differences and the dummy-value scan cannot run."}</li>
          <li>Earlier matching files are omitted from this review.</li></ul>
      </div>${skipAreaButton(area)}</section>`).join("")}</div>` : ""}
    <details class="detail-disclosure"><summary>Pre-checks and comparison baselines</summary>
      <h3>Pre-checks</h3><ul class="review-list">${checks.map(check => `<li>${check.passed ? "Passed" : "Needs review"} · ${escapeHtml(check.name)}</li>`).join("")}</ul>
      <h3>Baseline per component and area</h3><p>Searched earlier code drops from newest to oldest. Each area is resolved independently.</p>
      <div class="table-wrap"><table><thead><tr><th>Component</th><th>Area</th><th>Baseline</th><th>Revision / source</th></tr></thead><tbody>${baselineRows}${missingBaselineRows || (!baselineRows ? `<tr><td colspan="4" class="empty">No component directories were found.</td></tr>` : "")}</tbody></table></div>
    </details>
    ${releaseCoverageRows ? `<details class="detail-disclosure"><summary>Recent historical comparison coverage</summary><p>Coverage for the preceding five numbered drops; older discovered releases are in the workbooks.</p><div class="table-wrap"><table><thead><tr><th>Release</th><th>Component</th><th>Result</th><th>Details</th></tr></thead><tbody>${releaseCoverageRows}</tbody></table></div></details>` : ""}
    ${errorRows ? `<details class="detail-disclosure"><summary>JSON validation errors (${validationErrorCount})</summary>${isBlocked ? `<p>The dummy scan and approval stay blocked until all current-release JSON files are valid. Binary review remains available.</p>` : `<p>Errors are limited to the uploaded release and selected per-component baselines. Baseline parse errors use hash comparison for that file.</p>`}<div class="table-wrap"><table><thead><tr><th>Release and file</th><th>Line</th><th>Column</th><th>Error and context</th></tr></thead><tbody>${errorRows}</tbody></table></div>${isBlocked ? `<a class="button button-secondary" href="${api("/json-errors.csv")}">Download current-release error list</a>` : ""}</details>` : ""}
    ${duplicateRows ? `<details class="detail-disclosure"><summary>Duplicate JSON keys (${(validation.duplicates || []).length})</summary><div class="table-wrap"><table><tbody>${duplicateRows}</tbody></table></div></details>` : ""}
    <div class="footer-actions">
      <button class="button button-secondary" id="reupload-configs">Re-upload configs</button>
      <button class="button button-primary" data-go="1" ${pendingSkips.length ? "disabled" : ""}>${pendingSkips.length ? "Confirm missing steps to continue" : "Review comparisons"} <span>→</span></button>
    </div>`;
}

function renderCompare() {
  if (!state) return;
  const rows = (state.binaries || []).filter(row => row.status !== "Removed");
  const binariesMissing = (state.areas_missing || []).includes("Binaries");
  const changed = rows.filter(row => row.status !== "Unchanged").length;
  const components = [...new Set(rows.map(row => row.component))];
  const groups = components.map(component => {
    const baseline = state.baselines?.[`Binaries/${component}`];
    const groupRows = rows.filter(row => row.component === component).map(row => `<tr>
      <td><code>${escapeHtml(row.file)}</code></td><td>${escapeHtml(row.baseline_version)}</td>
      <td>${escapeHtml(row.current_version)}</td><td>${statusPill(row.status)}</td></tr>`).join("");
    const currentPath = `${state.folder_name}/Binaries/${component}`;
    const baselinePath = baseline ? `${baseline.code_drop}/${baseline.path}` : "No baseline found · new component";
    return `<div class="card component-group">
      <div class="component-heading"><div><strong>${escapeHtml(currentPath)} ↔ ${escapeHtml(baselinePath)}</strong>
        <small>${baseline ? state.target_type === "local_folder"
          ? "Baseline from local folder"
          : `Baseline SVN revision ${baseline.revision ? `r${escapeHtml(baseline.revision)}` : "N/A"}`
          : "All files are new"}</small></div>
        <button class="button button-secondary" data-change-baseline="Binaries/${escapeHtml(component)}" ${(state.baseline_options?.[`Binaries/${component}`] || []).length < 2 ? "disabled" : ""}>Change baseline</button></div>
      <div class="table-wrap"><table><thead><tr><th>File</th><th>Baseline version</th><th>Current version</th><th>Status</th></tr></thead><tbody>${groupRows}</tbody></table></div>
    </div>`;
  }).join("");
  document.querySelector("#screen-compare").innerHTML = `
    <div class="section-heading"><div><div class="eyebrow">STEP 02 / BINARIES</div><h2>Binaries and versions</h2><p>Each component is compared against its selected earlier code drop; use the workbook for every-release file comparisons.</p></div>
      <a class="button button-secondary" href="${api("/reports/Binaries.xlsx")}">Download Binaries.xlsx ↓</a></div>
    <div class="card card-pad">
      <h3 class="card-title">How to read this comparison</h3>
      <ul class="point-list">
        <li><strong>N/A:</strong> file has no readable PE version resource. A dash means that side has no matching file.</li>
        <li><strong>Changed:</strong> file bytes differ. Lower embedded versions are flagged separately.</li>
        <li>This view uses the selected baseline; the workbook includes every discovered earlier release and the previous-five coverage.</li>
      </ul>
    </div>
    <div class="card card-pad">
      <div class="baseline-row"><div><h3 class="card-title">Current folder · ${escapeHtml(state.folder_name)}</h3><p class="card-subtitle">Baselines resolved separately for each Binaries/Component path.</p></div>
        ${binariesMissing ? "" : `<label class="ack-label"><input id="binary-reviewed" type="checkbox" ${state.binary_reviewed ? "checked" : ""}> I reviewed the binary comparison</label>`}</div>
    </div>
    ${binariesMissing ? `<div class="missing-review-item"><div><strong>Binary review is unavailable.</strong><ul class="point-list"><li>No Binaries folder was uploaded, so versions and files cannot be compared.</li><li>This does not mean the binaries passed review.</li></ul></div>${skipAreaButton("Binaries")}</div>` : ""}
    <div class="summary-grid">
      <div class="metric"><strong>${rows.length}</strong><span>Binaries checked</span></div>
      <div class="metric"><strong>${changed}</strong><span>Changed or new</span></div>
      <div class="metric"><strong>${rows.filter(row => row.status === "New").length}</strong><span>New files</span></div>
      <div class="metric"><strong>${rows.filter(row => /same version|downgrade/i.test(row.status)).length}</strong><span>Version review flags</span></div>
    </div>
    ${groups || (binariesMissing ? "" : `<div class="card empty">No binary files were found in the uploaded Binaries folder.</div>`)}
    ${navButtons()}`;
}

function renderConfig() {
  if (!state) return;
  const allConfigs = state.configs || [];
  const configs = allConfigs.filter(config =>
    ["New", "Changed", "Invalid JSON", "Baseline invalid JSON"].includes(config.status)
  );
  if (activeConfig >= configs.length) activeConfig = 0;
  const selected = configs[activeConfig];
  const list = configs.map((config, index) =>
    `<button class="file-button ${index === activeConfig ? "active" : ""}" data-config="${index}">${escapeHtml(config.file)}<small>${escapeHtml(config.baseline?.code_drop ? `vs ${config.baseline.code_drop}` : "New · no baseline")} · ${escapeHtml(config.status)}</small></button>`
  ).join("");
  const changes = selected?.changes || [];
  const textLines = selected?.text_diff || [];
  const currentParseError = selected?.current_validation_error;
  const baselineParseError = selected?.baseline_validation_error;
  const textDiff = textLines.length
    ? `<div class="text-diff" aria-label="Line-by-line JSON diff">${textLines.map(line =>
      `<div class="${line.startsWith("+") && !line.startsWith("+++") ? "added" : line.startsWith("-") && !line.startsWith("---") ? "removed" : ""}">${escapeHtml(line) || "&nbsp;"}</div>`
    ).join("")}</div>`
    : `<div class="empty">No text-level JSON changes.</div>`;
  const changeItems = changes.map(change => `<li class="config-change-item">
    <strong>${statusPill(change.change)} <code>${escapeHtml(change.key_path)}</code></strong>
    <span><b>Previous:</b> ${escapeHtml(change.previous)}</span>
    <span><b>Current:</b> ${escapeHtml(change.current)}</span>
  </li>`).join("");
  const invalidJsonMessage = currentParseError
    ? `<div class="banner error"><strong>Invalid JSON in the uploaded file.</strong><br>${escapeHtml(currentParseError.message)} at line ${currentParseError.line}, column ${currentParseError.column}.<pre class="json-error-context">${escapeHtml(currentParseError.context || "No parse context is available for this file.")}</pre></div>`
    : baselineParseError
      ? `<div class="banner warning"><strong>Selected baseline is invalid JSON.</strong><br>${escapeHtml(baselineParseError.message)} at line ${baselineParseError.line}, column ${baselineParseError.column}.<pre class="json-error-context">${escapeHtml(baselineParseError.context || "No parse context is available for the baseline file.")}</pre></div>`
      : "";
  const changedCount = configs.length;
  document.querySelector("#screen-config").innerHTML = `
    <div class="section-heading"><div><div class="eyebrow">STEP 03 / CONFIG DIFF</div><h2>Changed configuration files</h2><p>Only new or changed files are shown here. Unchanged files and files that exist only in earlier releases are omitted.</p></div>
      <div class="heading-actions"><button id="capture-diff" type="button" class="button button-secondary">Capture screenshot</button><a class="button button-secondary" href="${api("/reports/Configs.xlsx")}">Download Configs.xlsx ↓</a></div></div>
    <div class="config-summary"><strong>${changedCount}</strong><span>file(s) needing config review</span><small>Files present only in earlier releases are omitted from the review and reports.</small></div>
    ${state.configs?.some(config => config.status === "Baseline invalid JSON") ? `<div class="banner warning">One or more previous-release JSON files are invalid. Their contents are not shown; the report uses SHA-256 comparison and lists the baseline parse errors.</div>` : ""}
    ${state.config_scan_status === "blocked: invalid JSON" ? `<div class="banner error">One or more current JSON files are invalid. Those files are reported with validation errors and cannot be semantically scanned; valid configs and binary comparisons remain available. See Validation Issues in Configs.xlsx.</div>` : ""}
    ${state.areas_missing?.includes("Configs") ? `<div class="missing-review-item"><div><strong>Config review is unavailable.</strong><ul class="point-list"><li>No Configs folder was uploaded, so config diffs and dummy scanning did not run.</li><li>This is a skipped scan, not a clean scan.</li></ul></div>${skipAreaButton("Configs")}</div>` : ""}
    ${selected ? `<div class="config-layout">
      <nav class="card file-list" aria-label="Changed configuration files">${list}</nav>
      <article class="card card-pad" id="config-diff-card">
        <div class="diff-path"><strong>${escapeHtml(state.folder_name)}/Configs/${escapeHtml(selected.file)}</strong>
          <span>${statusPill(selected.status)}${selected.baseline ? ` · Compared with ${escapeHtml(selected.baseline.code_drop)}` : " · No earlier file"}</span></div>
        ${invalidJsonMessage}
        ${changeItems ? `<ul class="config-change-list">${changeItems}</ul>` : `<p class="empty">This file is new; there are no previous values to compare.</p>`}
        ${textLines.length ? `<details class="detail-disclosure"><summary>View line-by-line diff</summary>${textDiff}</details>` : ""}
      </article>
    </div>` : `<div class="empty">${state.areas_missing?.includes("Configs")
      ? "No current configuration files were uploaded. Earlier-only files are not shown here."
      : allConfigs.some(config => config.status === "Unchanged")
        ? "No changed files. All current configuration files match their selected baselines."
        : "No current configuration files are available to compare."}</div>`}
    ${navButtons()}`;
}

function renderDummy() {
  if (!state) return;
  const findings = state.findings || [];
  const acknowledged = new Set(state.acknowledged || []);
  const findingItems = findings.map(finding => `<li class="finding-item">
    <div><strong>${statusPill(finding.severity)} ${escapeHtml(finding.file)}</strong>
      <ul class="point-list">${findingContext(finding)}<li>Key: <code>${escapeHtml(finding.key_path)}</code></li><li>Matched value: <code>${escapeHtml(finding.value)}</code></li><li>Rule: ${escapeHtml(finding.pattern)}</li></ul></div>
    ${finding.severity === "Warning"
      ? `<label class="ack-label"><input type="checkbox" data-ack="${escapeHtml(finding.id)}" ${acknowledged.has(finding.id) ? "checked" : ""}> Acknowledge</label>`
      : ""}</li>`).join("");
  const blockers = findings.filter(item => item.severity === "Blocker").length;
  const warnings = findings.filter(item => item.severity === "Warning").length;
  document.querySelector("#screen-dummy").innerHTML = `
    <div class="section-heading"><div><div class="eyebrow">STEP 04 / JSON SCAN</div><h2>Dummy value scan</h2><p>Checks JSON config values against the versioned rules file. If Configs are missing, the scan is unavailable and must be explicitly skipped.</p></div>
      <a class="button button-secondary" href="${api("/reports/Configs.xlsx")}">Download Scan Report ↓</a></div>
    <div class="summary-grid">
      <div class="metric"><strong>${findings.length}</strong><span>Findings</span></div>
      <div class="metric"><strong>${blockers}</strong><span>Blockers</span></div>
      <div class="metric"><strong>${warnings}</strong><span>Warnings</span></div>
    </div>
    ${state.config_scan_status === "not run: Configs directory missing" ? `<div class="missing-review-item"><div><strong>Dummy scan was not run.</strong><ul class="point-list"><li>The uploaded ZIP has no Configs folder or JSON files for the rules to inspect.</li><li>This result is “Skipped,” not “Passed.”</li><li>Upload a Configs ZIP if configuration checks are expected; otherwise confirm skipping the Configs step.</li></ul></div>${skipAreaButton("Configs")}</div>` :
      state.config_scan_status === "blocked: invalid JSON" ? `<div class="banner error">Dummy scan was blocked because one or more JSON files failed validation. See Validation Issues in Configs.xlsx.</div>` :
      blockers ? `<div class="banner error">${blockers} blocker(s) must be fixed. Re-upload the corrected Configs ZIP and run a complete re-scan before approval.</div>` :
      warnings ? `<div class="banner warning">No blockers remain. Acknowledge each warning before uploading.</div>` :
        `<div class="banner">${state.validation?.checked ? "No dummy values found. The full scan completed against the current config files." : "No JSON config files were present to scan."}</div>`}
    ${findingItems ? `<ul class="finding-list">${findingItems}</ul>` : `<p class="empty">${state.configs_present ? "No configured dummy values were found in the scanned JSON files." : "No findings are available because there were no Configs files to scan."}</p>`}
    ${navButtons()}`;
}

function renderApprove() {
  if (!state) return;
  const findings = state.findings || [];
  const blockers = findings.filter(item => item.severity === "Blocker");
  const warnings = findings.filter(item => item.severity === "Warning");
  const acknowledged = new Set(state.acknowledged || []);
  const warningsAcknowledged = warnings.every(item => acknowledged.has(item.id));
  const missingAreas = new Set(state.areas_missing || []);
  const skippedAreas = new Set(state.skipped_areas || []);
  const binariesReady = missingAreas.has("Binaries")
    ? skippedAreas.has("Binaries")
    : Boolean(state.binary_reviewed);
  const configsReady = missingAreas.has("Configs")
    ? skippedAreas.has("Configs")
    : !state.validation?.failed;
  const scanReady = missingAreas.has("Configs")
    ? skippedAreas.has("Configs")
    : Boolean(state.rescan_completed) && blockers.length === 0;
  const checks = [
    ["Folder structure and naming valid", (state.structure_checks || []).every(check => check.passed)],
    [missingAreas.has("Configs") ? "Config review explicitly skipped — no Configs folder" : `All config JSON files valid (${state.validation?.checked || 0} files)`, configsReady],
    [missingAreas.has("Binaries") ? "Binary review explicitly skipped — no Binaries folder" : "Binary versions reviewed", binariesReady],
    [missingAreas.has("Configs") ? "Dummy scan explicitly skipped — no Configs to scan" : "Dummy-value re-scan has no blockers", scanReady],
    ["Warnings acknowledged", warningsAcknowledged]
  ];
  const checkRows = checks.map(([label, done]) => `<li class="check-row"><span class="check-state ${done ? "" : "open"}">${done ? "DONE" : "OPEN"}</span><span>${escapeHtml(label)}</span></li>`).join("");
  const recheckChanges = state.finding_changes || null;
  let findingRows = "";
  if (recheckChanges) {
    const changes = [
      ...recheckChanges.fixed.map(item => ({ ...item, status: "Fixed" })),
      ...recheckChanges.still_present.map(item => ({ ...item, status: `Still present: ${item.finding.severity.toLowerCase()}` })),
      ...recheckChanges.new.map(item => ({ ...item, status: `New finding: ${item.finding.severity.toLowerCase()}` }))
    ];
    findingRows = changes.map(item => `<li class="finding-item"><div><strong>${statusPill(item.status)} ${escapeHtml(item.finding.file)}</strong><ul class="point-list">${findingContext(item.finding)}<li>Key: <code>${escapeHtml(item.finding.key_path)}</code></li><li>Previous: <code>${escapeHtml(item.original_value)}</code></li><li>Current: <code>${escapeHtml(item.current_value)}</code></li></ul></div></li>`).join("");
  } else {
    findingRows = findings.map(item => `<li class="finding-item"><div><strong>${statusPill(item.severity)} ${escapeHtml(item.file)}</strong><ul class="point-list">${findingContext(item)}<li>Key: <code>${escapeHtml(item.key_path)}</code></li><li>Value: <code>${escapeHtml(item.value)}</code></li></ul></div></li>`).join("");
  }
  const localOnly = state.target_type === "local_folder";
  const canUpload = !localOnly && checks.every(([, done]) => done) && !state.validation?.failed;
  const uploaded = state.upload;
  document.querySelector("#screen-approve").innerHTML = `
    <div class="section-heading"><div><div class="eyebrow">STEP 05 / APPROVAL</div><h2>Review and approve</h2><p>Confirm each review result and download the complete report before approval.</p></div></div>
    ${localOnly ? `<div class="banner warning"><strong>Local comparison only.</strong> Review and report generation are available, but SVN upload is disabled. Use a repository URL for remote commits.</div>` : ""}
    ${uploaded ? `<div class="banner"><strong>Release committed successfully.</strong> Revision r${escapeHtml(uploaded.revision)} · ${escapeHtml(uploaded.url)} · Approved by ${escapeHtml(uploaded.approver)}.</div>` : ""}
    <div class="summary-grid">
      <div class="metric"><strong>${(state.binaries || []).filter(item => !["Unchanged", "Removed"].includes(item.status)).length}</strong><span>Binaries changed</span></div>
      <div class="metric"><strong>${(state.configs || []).filter(item => item.status === "Changed" || item.status === "New").length}</strong><span>Config files changed</span></div>
      <div class="metric"><strong>${blockers.length}</strong><span>Dummy blockers remaining</span></div>
      <div class="metric"><strong>${warnings.filter(item => acknowledged.has(item.id)).length}</strong><span>Warnings acknowledged</span></div>
    </div>
    <div class="card card-pad">
      <div class="baseline-row"><div><h3 class="card-title">${state.configs_present ? "Dummy value re-check after correction" : "Dummy scan status"}</h3><p class="card-subtitle">${state.configs_present ? `Last scan ${escapeHtml(state.scanned_at || "")} · folder SHA-256 ${escapeHtml((state.folder_hash || "").slice(0, 20))}…` : "No Configs directory was included; scanning is skipped and binary-only review may continue."}</p></div>
        ${state.configs_present ? `<button class="button button-secondary" id="rescan-configs" ${uploaded ? "disabled" : ""}>Re-scan configs</button>` : ""}</div>
      <p class="muted">When Configs are present, each re-scan requires a fresh Configs ZIP upload; the server never scans an earlier working copy.</p>
      ${blockers.length ? `<div class="banner error">${blockers.length} blocker(s) remain. Upload stays disabled until a new scan shows none.</div>` : ""}
      ${findingRows ? `<ul class="finding-list">${findingRows}</ul>` : `<p class="empty">${state.configs_present ? "No dummy-value findings remain." : "No dummy scan ran: the uploaded ZIP has no Configs folder."}</p>`}
    </div>
    <div class="card card-pad">
      <h3 class="card-title">Release checklist</h3>
      <ul class="review-list">${checkRows}</ul>
    </div>
    <div class="card card-pad">
      <h3 class="card-title">Final review reports</h3>
      <p class="card-subtitle">The complete bundle contains both workbooks plus a short release summary. Download individual workbooks if you only need one area.</p>
      <div class="actions-right report-actions">
        <a class="button button-primary" href="${api("/reports/Release-Review.zip")}">Download complete report bundle</a>
        <a class="button button-secondary" href="${api("/reports/Binaries.xlsx")}">Binaries.xlsx</a>
        <a class="button button-secondary" href="${api("/reports/Configs.xlsx")}">Configs.xlsx</a>
      </div>
      <div class="form-grid">
        <label class="field"><span>Approver name <b class="required">*</b></span><input id="approver" placeholder="Your name" ${uploaded ? "disabled" : ""}></label>
        <label class="field"><span>Commit message <b class="required">*</b></span><input id="commit-message" value="${escapeHtml(state.folder_name)} release" ${uploaded ? "disabled" : ""}></label>
      </div>
      <div class="credentials-grid form-grid" style="margin-top:14px">
        <label class="field"><span>SVN username</span><input id="upload-username" autocomplete="username" ${uploaded ? "disabled" : ""}></label>
        <label class="field"><span>SVN password</span><input id="upload-password" type="password" autocomplete="current-password" ${uploaded ? "disabled" : ""}><small>Used for the commit only; not retained.</small></label>
      </div>
    </div>
    <div class="upload-confirm card"><div class="card-pad">
      <h3>Upload ${escapeHtml(state.folder_name)} to SVN?</h3>
      <p>${localOnly ? "Local folder: " : "Destination: "}<code>${escapeHtml(state.target_url)}${localOnly ? "" : `/${escapeHtml(state.folder_name)}`}</code>. ${localOnly ? "No SVN changes will be made in local comparison mode." : "The SVN destination must not already contain this code drop."}</p>
      <div class="footer-actions"><span class="muted">${localOnly ? "Offline comparison; upload is disabled." : canUpload ? "All release checks passed." : "Complete every open checklist item before uploading."}</span>
        <button class="button button-primary" id="confirm-upload" ${!canUpload || uploaded ? "disabled" : ""}>${localOnly ? "Upload unavailable" : "Confirm and upload"}</button></div>
    </div></div>
    ${uploaded ? "" : navButtons()}`;
}

function applyState(newState) {
  state = newState;
  document.body.classList.add("has-review");
  document.querySelectorAll(".step-link").forEach(button => {
    button.disabled = !state;
  });
  document.querySelector(".step-link[data-step='0']").disabled = false;
  renderSelectResults();
  if (currentStep === 1) renderCompare();
  if (currentStep === 2) renderConfig();
  if (currentStep === 3) renderDummy();
  if (currentStep === 4) renderApprove();
}

async function submitSource(event) {
  event.preventDefault();
  clearAlert();
  const archive = document.querySelector("#archive").files[0];
  if (!archive) return showAlert("Choose a code drop ZIP file first.");
  const targetUrl = document.querySelector("#target-url").value.trim();
  const username = document.querySelector("#svn-username").value.trim();
  const password = document.querySelector("#svn-password").value;
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(targetUrl) && !isSvnTarget(targetUrl)) {
    return showAlert("Use an SVN URL (https://, http://, svn://, svn+ssh://, or file://) or an absolute local folder path.");
  }
  if (isSvnTarget(targetUrl) && (!username || !password)) {
    return showAlert("Enter both your SVN username and password to read the repository.");
  }
  setBusy(true, "Extracting ZIP and comparing with earlier code drops…");
  try {
    const created = await requestJson("/api/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        folder_name: document.querySelector("#folder-name").value,
        target_url: targetUrl
      })
    });
    sessionId = created.id;
    const form = new FormData();
    form.append("svn_username", document.querySelector("#svn-username").value);
    form.append("svn_password", document.querySelector("#svn-password").value);
    form.append("archive", archive);
    const started = await requestJson(api("/source"), { method: "POST", body: form });
    if (started.status === "analyzing") {
      let result;
      do {
        await new Promise(resolve => setTimeout(resolve, 800));
        result = await requestJson(api(""));
        busyText.textContent = result.state?.progress || "Reviewing your code drop…";
      } while (result.status === "analyzing");
      if (result.status === "failed") throw new Error(result.state?.error || "Source analysis failed.");
      state = result.state;
    } else {
      state = started;
    }
    applyState(state);
    document.querySelector("#select-results").scrollIntoView({ behavior: "smooth", block: "start" });
    if (state.validation.failed) {
      showAlert(`${state.validation.failed} JSON file(s) failed validation. Fix them, then re-upload the Configs ZIP.`, "warning");
    } else {
      showAlert("Source checked. Review the per-component baselines, then start the comparison.", "success");
    }
  } catch (error) {
    showAlert(error.message);
  } finally {
    setBusy(false);
  }
}

async function rescanConfigs(file) {
  if (!file) return;
  clearAlert();
  setBusy(true, "Validating the new Configs ZIP and re-running the full scan…");
  try {
    const form = new FormData();
    form.append("archive", file);
    form.append("svn_username", document.querySelector("#svn-username").value);
    form.append("svn_password", document.querySelector("#svn-password").value);
    state = await requestJson(api("/rescan"), { method: "POST", body: form });
    applyState(state);
    setStep(4);
    if (state.validation.failed) {
      showAlert(`${state.validation.failed} JSON file(s) are still invalid. Fix them and upload another Configs ZIP.`, "warning");
    } else {
      showAlert("Configs replaced and the full scan completed.", "success");
    }
  } catch (error) {
    showAlert(error.message);
  } finally {
    setBusy(false);
  }
}

async function changeBaseline(select) {
  if (!select?.value) return;
  clearAlert();
  setBusy(true, "Loading the selected SVN baseline…");
  try {
    const form = new FormData();
    form.append("path", select.dataset.path);
    form.append("code_drop", select.value);
    form.append("svn_username", document.querySelector("#svn-username").value);
    form.append("svn_password", document.querySelector("#svn-password").value);
    state = await requestJson(api("/baseline"), { method: "POST", body: form });
    applyState(state);
    showAlert("Baseline changed and reports were regenerated.", "success");
  } catch (error) {
    showAlert(error.message);
  } finally {
    setBusy(false);
  }
}

async function updateReviewed(reviewed) {
  try {
    state = await requestJson(api("/review"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reviewed })
    });
    applyState(state);
  } catch (error) {
    showAlert(error.message);
  }
}

async function confirmAreaSkip(area) {
  try {
    state = await requestJson(api("/skip-area"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ area })
    });
    applyState(state);
    showAlert(`${area} review marked as skipped because its folder was not in the ZIP.`, "success");
  } catch (error) {
    showAlert(error.message);
  }
}

async function updateAcknowledgement(findingId, acknowledged) {
  try {
    state = await requestJson(api("/acknowledge"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_id: findingId, acknowledged })
    });
    applyState(state);
  } catch (error) {
    showAlert(error.message);
  }
}

async function confirmUpload() {
  clearAlert();
  const button = document.querySelector("#confirm-upload");
  button.disabled = true;
  try {
    state = await requestJson(api("/upload"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        approver: document.querySelector("#approver").value,
        commit_message: document.querySelector("#commit-message").value,
        svn_username: document.querySelector("#upload-username").value,
        svn_password: document.querySelector("#upload-password").value
      })
    });
    applyState(state);
    showAlert(`SVN commit completed at revision r${state.upload.revision}.`, "success");
  } catch (error) {
    showAlert(error.message);
    button.disabled = false;
  }
}

async function captureDiff() {
  const element = document.querySelector("#config-diff-card");
  if (!element) return;
  const markup = new XMLSerializer().serializeToString(element.cloneNode(true));
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="800"><foreignObject width="100%" height="100%"><div xmlns="http://www.w3.org/1999/xhtml" style="padding:20px;background:white;font:14px Arial;color:#183b32">${markup}</div></foreignObject></svg>`;
  const image = new Image();
  image.onload = () => {
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth || 1100;
    canvas.height = image.naturalHeight || 800;
    canvas.getContext("2d").drawImage(image, 0, 0);
    canvas.toBlob(blob => {
      if (!blob) return showAlert("The browser could not capture this diff as an image.");
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `${state.folder_name}-${state.configs[activeConfig].file.replace(/[\\/]/g, "_")}.png`;
      link.click();
      URL.revokeObjectURL(link.href);
    }, "image/png");
  };
  image.onerror = () => showAlert("The browser could not capture this diff as an image.");
  image.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

document.querySelector("#source-form").addEventListener("submit", submitSource);
document.querySelector("#target-url").addEventListener("input", updateTargetMode);
document.querySelector("#browse-file").addEventListener("click", () => document.querySelector("#archive").click());
document.querySelector("#archive").addEventListener("change", event => {
  document.querySelector("#file-label").textContent = event.target.files[0]?.name || "Drop your code drop ZIP here";
});
const dropZone = document.querySelector(".drop-zone");
dropZone.addEventListener("dragover", event => { event.preventDefault(); dropZone.classList.add("dragover"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
dropZone.addEventListener("drop", event => {
  event.preventDefault();
  dropZone.classList.remove("dragover");
  const file = event.dataTransfer.files[0];
  if (file) {
    const transfer = new DataTransfer();
    transfer.items.add(file);
    document.querySelector("#archive").files = transfer.files;
    document.querySelector("#file-label").textContent = file.name;
  }
});

document.querySelectorAll(".step-link").forEach(button => button.addEventListener("click", () => {
  if (!button.disabled) setStep(Number(button.dataset.step));
}));

document.addEventListener("click", event => {
  const next = event.target.closest("[data-go]");
  if (next && !next.disabled) {
    clearAlert();
    setStep(Number(next.dataset.go));
    return;
  }
  const skipArea = event.target.closest("[data-skip-area]");
  if (skipArea) {
    confirmAreaSkip(skipArea.dataset.skipArea);
    return;
  }
  const config = event.target.closest("[data-config]");
  if (config) {
    activeConfig = Number(config.dataset.config);
    renderConfig();
    return;
  }
  const changeBaselineButton = event.target.closest("[data-change-baseline]");
  if (changeBaselineButton) {
    const baselinePath = changeBaselineButton.dataset.changeBaseline;
    updateTargetMode();
    setStep(0);
    const select = [...document.querySelectorAll(".baseline-choice")]
      .find(item => item.dataset.path === baselinePath);
    if (select) {
      select.scrollIntoView({ behavior: "smooth", block: "center" });
      select.focus();
    } else {
      showAlert("There is no alternate earlier SVN baseline for this component.", "warning");
    }
    return;
  }
  if (event.target.closest("#reupload-configs")) {
    document.querySelector("#rescan-file").click();
    return;
  }
  if (event.target.closest("#rescan-configs")) {
    document.querySelector("#rescan-file").click();
    return;
  }
  if (event.target.closest("#capture-diff")) captureDiff();
  if (event.target.closest("#confirm-upload")) confirmUpload();
});

document.addEventListener("change", event => {
  if (event.target.matches(".baseline-choice")) changeBaseline(event.target);
  if (event.target.matches("#binary-reviewed")) updateReviewed(event.target.checked);
  if (event.target.matches("[data-ack]")) updateAcknowledgement(event.target.dataset.ack, event.target.checked);
});

document.querySelector("#rescan-file").addEventListener("change", event => {
  rescanConfigs(event.target.files[0]);
  event.target.value = "";
});

setStep(0);
