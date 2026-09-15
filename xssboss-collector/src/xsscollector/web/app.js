"use strict";

const state = {
  config: null,
  runs: [],
  latest: null,
  inventory: null,
  resultCategory: "endpoints",
  resultPage: 0,
  selectedJsFiles: [],
  diff: null,
};

const titles = {
  overview: ["Workspace", "Overview"],
  "new-run": ["Guided workflow", "New run"],
  runs: ["Audit trail", "Run history"],
  compare: ["Change intelligence", "Compare runs"],
  results: ["Evidence explorer", "Results"],
};

const categoryLabels = {
  endpoints: "Endpoints", files: "JS files", functions: "Functions", inputs: "Inputs",
  outputs: "Outputs", sources: "Sources", sinks: "Sinks", calls: "Calls", flows: "Flows",
  modules: "Modules", symbols: "Symbols", http_status: "HTTP status", request_headers: "Request headers",
  response_headers: "Response headers", technologies: "Technologies", evidence: "Evidence",
  parameters: "Parameters", observations: "Observations", relationships: "Relationships", artifacts: "Artifacts",
  js_files: "JS files", js_functions: "JS functions", js_inputs: "JS inputs", js_outputs: "JS outputs",
  js_sources: "JS sources", js_sinks: "JS sinks", js_calls: "JS calls", js_flows: "JS flows",
  js_modules: "JS modules", js_symbols: "JS symbols",
};

const preferredColumns = {
  endpoints: ["method", "url_pattern", "source", "title", "technologies", "parameters"],
  files: ["file_url", "size_bytes", "module_kind", "source_map_url", "sha256", "parse_warnings"],
  functions: ["file_url", "function_key", "kind", "parameters", "start_line", "end_line", "async_flag", "complexity"],
  inputs: ["file_url", "function_key", "name", "kind", "default_value", "type_hint", "line"],
  outputs: ["file_url", "function_key", "kind", "expression", "line"],
  sources: ["file_url", "function_key", "kind", "variable", "input_name", "expression", "line", "confidence"],
  sinks: ["file_url", "function_key", "kind", "category", "severity", "value_expression", "line", "confidence"],
  calls: ["file_url", "caller", "callee", "arguments", "awaited", "optional", "line"],
  flows: ["file_url", "function_key", "source_kind", "source_name", "sink_kind", "path", "sanitized", "confidence", "line"],
  modules: ["file_url", "kind", "module", "names", "line"],
  symbols: ["file_url", "symbol_kind", "name"],
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
}

function human(value) {
  const acronyms = { js: "JS", http: "HTTP", id: "ID", url: "URL", sha256: "SHA-256" };
  return String(value).split("_").map(part => acronyms[part] || part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}

function valueText(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  if (value === 1 || value === 0) return String(value);
  return String(value);
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  let data;
  try { data = await response.json(); } catch { data = {}; }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function jsonPost(path, data) {
  return api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
}

function navigate(name) {
  if (!titles[name]) return;
  $$(".view").forEach(view => view.classList.toggle("active", view.id === `view-${name}`));
  $$(".nav-item[data-view]").forEach(item => item.classList.toggle("active", item.dataset.view === name));
  $("#viewEyebrow").textContent = titles[name][0];
  $("#viewTitle").textContent = titles[name][1];
  $("#sidebar").classList.remove("open");
  history.replaceState(null, "", `#${name}`);
  $("#main").focus({ preventScroll: true });
  if (name === "results" && state.latest?.run_id && !state.inventory) loadInventory(state.latest.run_id);
}

function setMode(mode) {
  $$("[data-mode]").forEach(tab => tab.setAttribute("aria-selected", String(tab.dataset.mode === mode)));
  $$("[data-form]").forEach(form => form.classList.toggle("active", form.dataset.form === mode));
}

function metric(label, value, tone = "") {
  const card = element("article", `metric ${tone}`.trim());
  card.append(element("strong", "", Number(value || 0).toLocaleString()), element("span", "", label));
  return card;
}

function renderMetrics(target, stats) {
  target.replaceChildren(
    metric("Endpoints", stats?.endpoints),
    metric("JS functions", stats?.js_functions),
    metric("Sources", stats?.js_sources),
    metric("Sinks", stats?.js_sinks),
  );
}

function modeLabel(mode) {
  const labels = { "analyze-js": "JS analysis", live: "Site collection", "import:har": "HAR import", "import:burp": "Burp import", "import:openapi": "OpenAPI import", "import:urls": "URL import" };
  return labels[mode] || human(mode);
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function duration(run) {
  if (!run.finished_at) return "Running";
  const ms = new Date(run.finished_at) - new Date(run.started_at);
  if (!Number.isFinite(ms)) return "—";
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
  return `${(ms / 60000).toFixed(1)} min`;
}

function appendCell(row, content) {
  const cell = element("td", "", content);
  cell.title = valueText(content);
  row.append(cell);
}

function runRow(run, detailed = false) {
  const row = document.createElement("tr");
  appendCell(row, `#${run.id}`);
  appendCell(row, modeLabel(run.mode));
  const statusCell = document.createElement("td");
  statusCell.append(element("span", `status-badge ${run.status === "completed" ? "" : "failed"}`.trim(), human(run.status)));
  row.append(statusCell);
  appendCell(row, formatDate(run.started_at));
  if (detailed) appendCell(row, duration(run));
  const stats = run.collector_stats || {};
  appendCell(row, stats.endpoints || 0);
  if (detailed) appendCell(row, stats.js_functions || 0);
  appendCell(row, stats.js_sinks || 0);
  const actions = document.createElement("td");
  const view = element("button", "table-action", "View");
  view.type = "button";
  view.addEventListener("click", () => { navigate("results"); loadInventory(run.id); });
  actions.append(view);
  row.append(actions);
  return row;
}

function renderRuns() {
  const recent = $("#recentRuns");
  recent.replaceChildren(...state.runs.slice(0, 5).map(run => runRow(run)));
  if (!state.runs.length) recent.append(emptyTableRow(7, "No runs yet. Start with a guided run."));
  filterRuns();
  const options = state.runs.map(run => {
    const option = element("option", "", `#${run.id} · ${modeLabel(run.mode)} · ${formatDate(run.started_at)}`);
    option.value = run.id;
    return option;
  });
  [$("#fromRun"), $("#toRun"), $("#resultRun")].forEach(select => select.replaceChildren(...options.map(option => option.cloneNode(true))));
  if (state.runs.length) {
    $("#toRun").value = state.runs[0].id;
    $("#resultRun").value = state.latest?.run_id || state.runs[0].id;
    if (state.runs[1]) $("#fromRun").value = state.runs[1].id;
  }
}

function filterRuns() {
  const query = ($("#runSearch")?.value || "").toLowerCase().trim();
  const filtered = state.runs.filter(run => JSON.stringify(run).toLowerCase().includes(query));
  const body = $("#runsTable");
  body.replaceChildren(...filtered.map(run => runRow(run, true)));
  if (!filtered.length) body.append(emptyTableRow(9, query ? "No runs match this search." : "No runs yet."));
  $("#runCount").textContent = `${filtered.length} of ${state.runs.length} runs`;
}

function emptyTableRow(columns, message) {
  const row = document.createElement("tr");
  const cell = element("td", "muted", message);
  cell.colSpan = columns;
  row.append(cell);
  return row;
}

function populateSettings() {
  const config = state.config || {};
  $("#scopeAllow").value = (config.allow || []).join("\n");
  $("#scopeDeny").value = (config.deny || []).join("\n");
  $("#authorizedUse").checked = config.authorized_use !== false;
  $("#privateNetworks").checked = config.allow_private_networks !== false;
  $("#crawlProfile").value = config.profile || "standard";
  $("#maxPages").value = config.max_pages || 500;
  $("#maxDepth").value = config.max_depth ?? 2;
  $("#requestsPerSecond").value = config.requests_per_second || 2;
}

function updateAuthorization() {
  $("#authorizationBanner").hidden = true;
}

async function refreshState(firstLoad = false) {
  const data = await api("/api/state");
  state.config = data.config;
  state.runs = data.runs || [];
  state.latest = data.latest;
  renderMetrics($("#metricGrid"), data.latest);
  renderRuns();
  populateSettings();
  updateAuthorization();
  if (firstLoad && !data.configured) {
    $("#settingsDialog").showModal();
    toast("Set your authorized scope", "Confirm the exact systems you are permitted to assess.");
  }
  if (firstLoad && data.configured && location.hash === "#results" && data.latest?.run_id && !state.inventory) {
    await loadInventory(data.latest.run_id);
  }
}

function showLoading(title, text) {
  $("#loadingTitle").textContent = title;
  $("#loadingText").textContent = text;
  $("#loading").hidden = false;
  document.body.setAttribute("aria-busy", "true");
  $$('button[type="submit"]').forEach(button => { button.disabled = true; });
}

function hideLoading() {
  $("#loading").hidden = true;
  document.body.removeAttribute("aria-busy");
  $$('button[type="submit"]').forEach(button => { button.disabled = false; });
}

function toast(title, message, isError = false) {
  const node = element("div", `toast ${isError ? "error" : ""}`.trim());
  node.append(element("strong", "", title), element("span", "", message));
  $("#toasts").append(node);
  setTimeout(() => node.remove(), 5200);
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error(`Could not read ${file.name}`));
    reader.onload = () => resolve(String(reader.result).split(",", 2)[1]);
    reader.readAsDataURL(file);
  });
}

function supportedJs(files) {
  return [...files].filter(file => /\.(?:js|mjs|cjs|jsx|ts|tsx)$/i.test(file.name));
}

function selectJsFiles(files) {
  state.selectedJsFiles = supportedJs(files);
  const size = state.selectedJsFiles.reduce((total, file) => total + file.size, 0);
  $("#jsFileSummary").textContent = state.selectedJsFiles.length ? `${state.selectedJsFiles.length} files · ${formatBytes(size)}` : "No supported files selected";
}

function formatBytes(value) {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}

async function submitJs(event) {
  event.preventDefault();
  if (!state.selectedJsFiles.length) { toast("Files required", "Choose at least one supported JS or TS file.", true); return; }
  showLoading("Analyzing JavaScript", "Mapping functions, inputs, outputs, sources, sinks, calls, and flows.");
  try {
    const files = await Promise.all(state.selectedJsFiles.map(async file => ({ name: file.webkitRelativePath || file.name, content: await fileToBase64(file) })));
    const data = await jsonPost("/api/analyze-js", { base_url: $("#jsBaseUrl").value, files });
    await completedRun(data);
  } catch (error) { toast("Analysis failed", error.message, true); } finally { hideLoading(); }
}

async function submitCollect(event) {
  event.preventDefault();
  showLoading("Collecting authorized URLs", "Following in-scope links with bounded GET-only requests.");
  try {
    const data = await jsonPost("/api/collect", { urls: $("#collectUrls").value });
    await completedRun(data);
  } catch (error) { toast("Collection failed", error.message, true); } finally { hideLoading(); }
}

async function submitImport(event) {
  event.preventDefault();
  const format = $("#importFormat").value;
  if (format === "mirror") {
    const supported = [...$("#mirrorFolder").files].filter(file => /\.(?:html?|xhtml|js|mjs|cjs|jsx|ts|tsx|css|json|map|xml|svg|txt|webmanifest)$/i.test(file.name));
    if (!supported.length) { toast("Folder required", "Choose a mirror folder containing security-relevant text assets.", true); return; }
    showLoading("Analyzing website mirror", "Mapping pages, assets, functions, sources, sinks, inputs, outputs, and data flows offline.");
    try {
      const files = await Promise.all(supported.map(async file => ({ name: file.webkitRelativePath || file.name, content: await fileToBase64(file) })));
      const data = await jsonPost("/api/import", { format, base_url: $("#openapiBase").value, files });
      await completedRun(data);
    } catch (error) { toast("Mirror import failed", error.message, true); } finally { hideLoading(); }
    return;
  }
  const file = $("#importFile").files[0];
  if (!file) { toast("File required", "Choose one capture or specification file.", true); return; }
  showLoading("Importing collection data", "Parsing the file offline and building its inventory.");
  try {
    const data = await jsonPost("/api/import", { format, base_url: $("#openapiBase").value, file: { name: file.name, content: await fileToBase64(file) } });
    await completedRun(data);
  } catch (error) { toast("Import failed", error.message, true); } finally { hideLoading(); }
}

async function completedRun(data) {
  toast("Run completed", `Run #${data.run.run_id} is ready to review.`);
  state.inventory = null;
  await refreshState();
  navigate("results");
  await loadInventory(data.run.run_id);
}

async function loadInventory(runId) {
  if (!runId) return;
  showLoading("Loading results", `Preparing the inventory for run #${runId}.`);
  try {
    state.inventory = await api(`/api/inventory?run=${encodeURIComponent(runId)}`);
    state.resultCategory = "endpoints";
    $("#resultRun").value = runId;
    $("#resultEmpty").hidden = true;
    $("#resultContent").hidden = false;
    renderMetrics($("#resultMetrics"), state.inventory.stats);
    const categories = ["endpoints", ...Object.keys(state.inventory.javascript || {})];
    const tabs = categories.map(name => {
      const count = inventoryRows(name).length;
      const tab = element("button", "", `${categoryLabels[name] || human(name)} (${count})`);
      tab.type = "button";
      tab.setAttribute("role", "tab");
      tab.setAttribute("aria-selected", String(name === state.resultCategory));
      tab.dataset.category = name;
      tab.addEventListener("click", () => { state.resultCategory = name; state.resultPage = 0; renderDataTabs(); renderResultTable(); });
      return tab;
    });
    $("#dataTabs").replaceChildren(...tabs);
    updateInventoryDownloads(runId);
    renderResultTable();
  } catch (error) { toast("Could not load results", error.message, true); } finally { hideLoading(); }
}

function inventoryRows(name = state.resultCategory) {
  if (!state.inventory) return [];
  return name === "endpoints" ? state.inventory.endpoints || [] : state.inventory.javascript?.[name] || [];
}

function renderDataTabs() {
  $$("[data-category]", $("#dataTabs")).forEach(tab => tab.setAttribute("aria-selected", String(tab.dataset.category === state.resultCategory)));
}

function renderResultTable() {
  const allRows = inventoryRows();
  const query = $("#resultSearch").value.toLowerCase().trim();
  const rows = allRows.filter(row => JSON.stringify(row).toLowerCase().includes(query));
  const pageSize = 100;
  const pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
  state.resultPage = Math.max(0, Math.min(state.resultPage, pageCount - 1));
  const visibleRows = rows.slice(state.resultPage * pageSize, (state.resultPage + 1) * pageSize);
  const preferred = preferredColumns[state.resultCategory] || [];
  const available = new Set(allRows.flatMap(row => Object.keys(row)));
  let columns = preferred.filter(key => available.has(key));
  if (!columns.length) columns = [...available].filter(key => !["id", "js_file_id", "endpoint_id"].includes(key)).slice(0, 10);
  $("#resultTableTitle").textContent = categoryLabels[state.resultCategory] || human(state.resultCategory);
  $("#resultTableCount").textContent = `${rows.length.toLocaleString()} of ${allRows.length.toLocaleString()} records`;
  $("#resultPage").textContent = `Page ${state.resultPage + 1} of ${pageCount}`;
  $("#resultPrevious").disabled = state.resultPage === 0;
  $("#resultNext").disabled = state.resultPage >= pageCount - 1;
  const headerRow = document.createElement("tr");
  columns.forEach(column => headerRow.append(element("th", "", human(column))));
  $("#resultHead").replaceChildren(headerRow);
  const bodyRows = visibleRows.map(item => {
    const row = document.createElement("tr");
    columns.forEach(column => appendCell(row, valueText(item[column])));
    return row;
  });
  $("#resultBody").replaceChildren(...bodyRows);
  if (!visibleRows.length) $("#resultBody").append(emptyTableRow(Math.max(columns.length, 1), query ? "No records match this search." : "No records in this category."));
}

function updateInventoryDownloads(runId) {
  $("#inventoryHtml").href = `/download/inventory?run=${runId}&format=html`;
  $("#inventoryJson").href = `/download/inventory?run=${runId}&format=json`;
  $("#inventoryCsv").href = `/download/inventory?run=${runId}&format=csv`;
}

async function compareRuns(event) {
  event.preventDefault();
  const from = $("#fromRun").value;
  const to = $("#toRun").value;
  if (from === to) { toast("Choose two different runs", "The earlier and later run cannot be the same.", true); return; }
  showLoading("Comparing runs", "Checking all 20 web, HTTP, evidence, and JavaScript categories.");
  try {
    state.diff = await api(`/api/diff?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
    renderDiff();
    $("#diffEmpty").hidden = true;
    $("#diffResults").hidden = false;
    $("#diffHtml").href = `/download/diff?from=${from}&to=${to}&format=html`;
    $("#diffJson").href = `/download/diff?from=${from}&to=${to}&format=json`;
    $("#diffMd").href = `/download/diff?from=${from}&to=${to}&format=markdown`;
    toast("Comparison ready", `${state.diff.summary.changed} changed records across ${state.diff.summary.categories} categories.`);
  } catch (error) { toast("Comparison failed", error.message, true); } finally { hideLoading(); }
}

function renderDiff() {
  const summary = state.diff.summary;
  $("#diffMetrics").replaceChildren(
    metric("Added", summary.added, "added"), metric("Removed", summary.removed, "removed"),
    metric("Changed", summary.changed, "changed"), metric("Unchanged", summary.unchanged),
  );
  filterDiff();
}

function filterDiff() {
  if (!state.diff) return;
  const query = $("#diffSearch").value.toLowerCase().trim();
  const categories = Object.entries(state.diff.categories).filter(([name]) => (categoryLabels[name] || human(name)).toLowerCase().includes(query));
  $("#diffCategories").replaceChildren(...categories.map(([name, changes]) => diffCategory(name, changes)));
}

function diffCategory(name, changes) {
  const details = element("details", "category-card");
  const summary = document.createElement("summary");
  const total = changes.added.length + changes.removed.length + changes.changed.length;
  summary.append(icon("table"), element("span", "", categoryLabels[name] || human(name)), element("span", "change-count", `${total} changes · ${changes.unchanged_count} unchanged`));
  details.append(summary);
  const grid = element("div", "change-grid");
  [["Added", changes.added], ["Removed", changes.removed], ["Changed", changes.changed]].forEach(([label, records]) => {
    const column = element("section", "change-column");
    column.append(element("h3", "", `${label} (${records.length})`));
    if (!records.length) column.append(element("span", "change-empty", "No records"));
    records.slice(0, 25).forEach(record => column.append(element("pre", "", JSON.stringify(record, null, 2))));
    if (records.length > 25) column.append(element("span", "change-empty", `Showing 25 of ${records.length}. Download the report for every record.`));
    grid.append(column);
  });
  details.append(grid);
  if (total > 0) details.open = true;
  return details;
}

async function saveSettings(event) {
  event.preventDefault();
  showLoading("Saving settings", "Validating authorization, scope, and collection limits.");
  try {
    await jsonPost("/api/setup", {
      allow: $("#scopeAllow").value, deny: $("#scopeDeny").value,
      authorized_use: $("#authorizedUse").checked, allow_private_networks: $("#privateNetworks").checked,
      profile: $("#crawlProfile").value, max_pages: $("#maxPages").value,
      max_depth: $("#maxDepth").value, requests_per_second: $("#requestsPerSecond").value,
    });
    $("#settingsDialog").close();
    await refreshState();
    toast("Settings saved", "Your scope and safety limits are active.");
  } catch (error) { toast("Could not save settings", error.message, true); } finally { hideLoading(); }
}

function bindEvents() {
  document.addEventListener("click", event => {
    const viewButton = event.target.closest("[data-view]");
    if (viewButton) navigate(viewButton.dataset.view);
    const quick = event.target.closest("[data-new-mode]");
    if (quick) { navigate("new-run"); setMode(quick.dataset.newMode); }
  });
  $$("[data-mode]").forEach(tab => tab.addEventListener("click", () => setMode(tab.dataset.mode)));
  $("#menuButton").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  $("#themeButton").addEventListener("click", () => {
    const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("collector-theme", theme);
  });
  $("#openSettings").addEventListener("click", () => { populateSettings(); $("#settingsDialog").showModal(); });
  $("#authorizeButton").addEventListener("click", () => { populateSettings(); $("#settingsDialog").showModal(); });
  $("#settingsForm").addEventListener("submit", saveSettings);
  $("#jsForm").addEventListener("submit", submitJs);
  $("#collectForm").addEventListener("submit", submitCollect);
  $("#importForm").addEventListener("submit", submitImport);
  $("#compareForm").addEventListener("submit", compareRuns);
  $("#chooseJsFiles").addEventListener("click", () => $("#jsFiles").click());
  $("#chooseJsFolder").addEventListener("click", () => $("#jsFolder").click());
  $("#jsFiles").addEventListener("change", event => selectJsFiles(event.target.files));
  $("#jsFolder").addEventListener("change", event => selectJsFiles(event.target.files));
  const drop = $("#jsDrop");
  ["dragenter", "dragover"].forEach(name => drop.addEventListener(name, event => { event.preventDefault(); drop.classList.add("dragover"); }));
  ["dragleave", "drop"].forEach(name => drop.addEventListener(name, event => { event.preventDefault(); drop.classList.remove("dragover"); }));
  drop.addEventListener("drop", event => selectJsFiles(event.dataTransfer.files));
  $("#importFile").addEventListener("change", event => { $("#importFileSummary").textContent = event.target.files[0]?.name || "or click to choose one file"; });
  $("#mirrorFolder").addEventListener("change", event => {
    const files = [...event.target.files].filter(file => /\.(?:html?|xhtml|js|mjs|cjs|jsx|ts|tsx|css|json|map|xml|svg|txt|webmanifest)$/i.test(file.name));
    const size = files.reduce((total, file) => total + file.size, 0);
    $("#mirrorFileSummary").textContent = files.length ? `${files.length} analyzable files · ${formatBytes(size)}` : "No supported files found";
  });
  $("#importFormat").addEventListener("change", event => {
    const mirror = event.target.value === "mirror";
    const needsBase = mirror || event.target.value === "openapi";
    $("#openapiBaseField").hidden = !needsBase;
    $("#importBaseLabel").textContent = mirror ? "Original site base URL" : "OpenAPI base URL";
    $("#importBaseHelp").textContent = mirror ? "Must match allowed scope; gives mirrored files their original web identities." : "Used to resolve relative routes.";
    $("#openapiBase").required = mirror;
    $("#openapiBase").placeholder = mirror ? "https://app.example.com/" : "https://api.example.com/";
    $("#importDrop").hidden = mirror;
    $("#mirrorDrop").hidden = !mirror;
    $("#importFile").required = !mirror;
    const accepts = { har: ".har,.json", burp: ".xml", openapi: ".json", urls: ".txt,.csv" };
    $("#importFile").accept = accepts[event.target.value] || "";
  });
  $("#runSearch").addEventListener("input", filterRuns);
  $("#resultSearch").addEventListener("input", () => { state.resultPage = 0; renderResultTable(); });
  $("#resultPrevious").addEventListener("click", () => { state.resultPage -= 1; renderResultTable(); });
  $("#resultNext").addEventListener("click", () => { state.resultPage += 1; renderResultTable(); });
  $("#diffSearch").addEventListener("input", filterDiff);
  $("#resultRun").addEventListener("change", event => loadInventory(event.target.value));
}

async function start() {
  document.documentElement.dataset.theme = localStorage.getItem("collector-theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  bindEvents();
  const requested = location.hash.slice(1);
  navigate(titles[requested] ? requested : "overview");
  try { await refreshState(true); }
  catch (error) { toast("Dashboard could not start", error.message, true); }
}

start();
