"use strict";

const $ = (selector) => document.querySelector(selector);
const state = {
  catalog: null,
  query: "",
  verdict: "all",
  platform: "all",
  limit: 25,
  descending: true,
  visible: [],
};

async function initialize() {
  try {
    const response = await fetch("./skills.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`scan database request failed (${response.status})`);
    state.catalog = await response.json();
    populateFilters();
    renderStats();
    renderTable();
    $("#loading-state").hidden = true;
  } catch (error) {
    const loading = $("#loading-state");
    loading.replaceChildren();
    const strong = document.createElement("strong");
    strong.textContent = "Could not load scan data";
    const small = document.createElement("small");
    small.textContent = error.message;
    loading.append(strong, small);
  }
}

function populateFilters() {
  const verdicts = [...new Set(state.catalog.skills.map((skill) => skill.verdict))].sort();
  appendOptions($("#verdict-filter"), verdicts);
  appendOptions($("#platform-filter"), state.catalog.platforms);
}

function appendOptions(select, values) {
  for (const value of values) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = titleCase(value);
    select.append(option);
  }
}

function renderStats() {
  $("#stat-scanned").textContent = formatCount(state.catalog.totalScanned);
  $("#stat-platforms").textContent = formatCount(state.catalog.platforms.length);
  $("#stat-latest").textContent = state.catalog.dataUpdatedAt
    ? shortDate(state.catalog.dataUpdatedAt)
    : "No scans";
  $("#data-status").textContent = state.catalog.dataUpdatedAt
    ? `Data through ${formatTimestamp(state.catalog.dataUpdatedAt)}`
    : "No completed assessments";
}

function renderTable() {
  const query = state.query.toLowerCase();
  let rows = state.catalog.skills.filter((skill) => {
    const matchesQuery = !query || searchableText(skill).includes(query);
    const matchesVerdict = state.verdict === "all" || skill.verdict === state.verdict;
    const matchesPlatform = state.platform === "all"
      || skill.platforms.some((platform) => platform.name === state.platform);
    return matchesQuery && matchesVerdict && matchesPlatform;
  });
  rows.sort((left, right) => {
    const order = left.detectedAt.localeCompare(right.detectedAt);
    return state.descending ? -order : order;
  });
  state.visible = rows;
  const shown = state.limit === "all" ? rows : rows.slice(0, state.limit);
  const body = $("#skill-rows");
  body.replaceChildren(...shown.map(skillRow));
  $("#empty-state").hidden = rows.length !== 0;
  $("#result-count").textContent = `${formatCount(shown.length)} of ${formatCount(rows.length)} matching scans`;
}

function searchableText(skill) {
  return [
    skill.name,
    skill.sha256,
    skill.skillId,
    skill.verdict,
    skill.maxSeverity,
    ...skill.platforms.flatMap((platform) => [platform.name, platform.id]),
  ].join(" ").toLowerCase();
}

function skillRow(skill) {
  const row = document.createElement("tr");

  const platformCell = document.createElement("td");
  const platformList = document.createElement("div");
  platformList.className = "platform-list";
  if (!skill.platforms.length) {
    const unavailable = document.createElement("span");
    unavailable.className = "platform-chip";
    unavailable.textContent = "Unattributed";
    platformList.append(unavailable);
  }
  for (const platform of skill.platforms) {
    const link = document.createElement("a");
    link.className = "platform-chip";
    link.href = platform.url;
    link.rel = "noreferrer";
    link.textContent = platform.name;
    platformList.append(link);
  }
  platformCell.append(platformList);

  const skillCell = document.createElement("td");
  const skillLink = document.createElement("a");
  skillLink.className = "skill-link";
  skillLink.href = skill.detailUrl;
  const skillName = document.createElement("strong");
  skillName.textContent = skill.name;
  const linkType = document.createElement("small");
  linkType.textContent = skill.graphAvailable ? "Open execution graph ↘" : "Local viewer instructions ↗";
  skillLink.append(skillName, linkType);
  skillCell.append(skillLink);

  const detectedCell = document.createElement("td");
  const detected = document.createElement("div");
  detected.className = "detected";
  const time = document.createElement("time");
  time.dateTime = skill.detectedAt;
  time.textContent = shortDate(skill.detectedAt);
  const ago = document.createElement("small");
  ago.textContent = relativeDate(skill.detectedAt);
  detected.append(time, ago);
  detectedCell.append(detected);

  const hashCell = document.createElement("td");
  const hash = document.createElement("code");
  hash.className = "hash";
  hash.title = skill.sha256;
  hash.textContent = skill.sha256;
  hashCell.append(hash);

  const verdictCell = document.createElement("td");
  const verdict = document.createElement("span");
  verdict.className = `verdict ${verdictClass(skill.verdict)}`;
  const verdictName = document.createElement("strong");
  verdictName.textContent = skill.verdict;
  const detail = document.createElement("small");
  detail.textContent = `${formatRisk(skill.riskScore)} · ${skill.maxSeverity}`;
  verdict.append(verdictName, detail);
  verdictCell.append(verdict);

  row.append(platformCell, skillCell, detectedCell, hashCell, verdictCell);
  return row;
}

function exportCsv() {
  const header = ["platforms", "skill", "detected_at", "sha256", "verdict", "risk_score", "severity", "run_id"];
  const rows = state.visible.map((skill) => [
    skill.platforms.map((platform) => platform.name).join("|"),
    skill.name,
    skill.detectedAt,
    skill.sha256,
    skill.verdict,
    skill.riskScore,
    skill.maxSeverity,
    skill.runId,
  ]);
  const csv = [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
  const url = URL.createObjectURL(new Blob([`${csv}\n`], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "skillsissue-scans.csv";
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function csvCell(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function verdictClass(verdict) {
  if (verdict === "malicious" || verdict === "benign") return verdict;
  return "unknown";
}

function formatRisk(score) {
  return Number.isFinite(Number(score)) ? `${Number(score).toFixed(0)} risk` : "risk n/a";
}

function formatCount(value) {
  return new Intl.NumberFormat().format(value || 0);
}

function formatTimestamp(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function shortDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? value
    : new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "2-digit" }).format(date);
}

function relativeDate(value) {
  const date = new Date(value);
  const days = Math.round((date.valueOf() - Date.now()) / 86_400_000);
  if (!Number.isFinite(days)) return "detection time unavailable";
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (Math.abs(days) < 31) return formatter.format(days, "day");
  const months = Math.round(days / 30);
  if (Math.abs(months) < 12) return formatter.format(months, "month");
  return formatter.format(Math.round(months / 12), "year");
}

function titleCase(value) {
  return String(value).replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

$("#search").addEventListener("input", (event) => {
  state.query = event.target.value.trim();
  renderTable();
});
$("#verdict-filter").addEventListener("change", (event) => {
  state.verdict = event.target.value;
  renderTable();
});
$("#platform-filter").addEventListener("change", (event) => {
  state.platform = event.target.value;
  renderTable();
});
$("#row-limit").addEventListener("change", (event) => {
  state.limit = event.target.value === "all" ? "all" : Number(event.target.value);
  renderTable();
});
$("#sort-detected").addEventListener("click", () => {
  state.descending = !state.descending;
  $("#sort-detected").textContent = `Detected ${state.descending ? "↓" : "↑"}`;
  renderTable();
});
$("#export").addEventListener("click", exportCsv);
document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    $("#search").focus();
  }
});

initialize();
