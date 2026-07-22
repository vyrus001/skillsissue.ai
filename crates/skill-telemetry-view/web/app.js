"use strict";

const $ = (selector) => document.querySelector(selector);
const canvas = $("#graph");
const context = canvas.getContext("2d");
const shell = $(".app-shell");

const COLORS = {
  process: "#e6f7ef",
  file: "#e8bd6d",
  socket: "#6dd6e8",
  fd: "#bb8df2",
  other: "#879994",
};

const state = {
  model: null,
  positions: new Map(),
  visible: [],
  zoom: 1,
  panX: 0,
  panY: 0,
  worldWidth: 1800,
  worldHeight: 900,
  categories: new Set(["process", "file", "socket", "fd", "other"]),
  search: "",
  transport: "all",
  direction: "all",
  selected: null,
  dragging: false,
  dragStart: null,
  pointerStart: null,
};

async function loadGraph({ preserveView = false } = {}) {
  $("#loading").hidden = false;
  const bucket = $("#bucket").value;
  const group = $("#group").value;
  try {
    const response = await fetch(`/api/graph?bucket_ns=${bucket}&group=${group}`);
    if (!response.ok) throw new Error(`graph request failed (${response.status})`);
    state.model = await response.json();
    renderHeader();
    renderStats();
    renderCategoryFilters();
    calculateLayout();
    applyFilters();
    if (!preserveView) fitGraph();
    else draw();
  } catch (error) {
    $("#loading").innerHTML = "";
    const strong = document.createElement("strong");
    strong.textContent = "Could not load the graph";
    const message = document.createElement("span");
    message.textContent = error.message;
    $("#loading").append(strong, message);
    return;
  }
  $("#loading").hidden = true;
}

function renderHeader() {
  const { meta } = state.model;
  $("#run-id").textContent = meta.runId || shortSource(meta.source);
  $("#status-pill").textContent = meta.status || "loaded";
  const parts = [];
  if (meta.startedAt) parts.push(formatIso(meta.startedAt));
  if (meta.finishedAt) parts.push(formatIso(meta.finishedAt));
  $("#run-window").textContent = parts.join(" → ");
}

function renderStats() {
  const model = state.model;
  const values = [
    [formatCount(model.eventCount), "events"],
    [formatCount(model.processCount), "processes"],
    [formatCount(model.activityNodeCount), "activity nodes"],
    [formatDuration(model.minTimestampNs, model.maxTimestampNs), "duration"],
  ];
  const target = $("#trace-stats");
  target.replaceChildren();
  for (const [value, label] of values) {
    const card = document.createElement("div");
    card.className = "stat";
    const strong = document.createElement("strong");
    strong.textContent = value;
    const span = document.createElement("span");
    span.textContent = label;
    card.append(strong, span);
    target.append(card);
  }
  const note = $("#coverage-note");
  if (model.representedEventCount === model.eventCount) {
    note.className = "coverage-note";
    note.textContent = `All ${formatCount(model.eventCount)} parsed events remain reachable beneath nodes or relationship edges. ${formatCount(model.meta.malformedLines)} malformed line(s) were reported separately.`;
  } else {
    note.className = "coverage-note warning";
    note.textContent = `${formatCount(model.representedEventCount)} of ${formatCount(model.eventCount)} events are represented.`;
  }
}

function renderCategoryFilters() {
  const target = $("#category-filters");
  target.replaceChildren();
  const labels = { process: "Process", file: "File", socket: "Socket", fd: "FD lifecycle", other: "Other" };
  for (const category of ["process", "file", "socket", "fd", "other"]) {
    const row = document.createElement("label");
    row.className = "check-row";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = state.categories.has(category);
    input.addEventListener("change", () => {
      if (input.checked) state.categories.add(category);
      else state.categories.delete(category);
      applyFilters();
    });
    const name = document.createElement("span");
    name.textContent = labels[category];
    const count = document.createElement("b");
    count.textContent = formatCount(state.model.facets.categories[category] || 0);
    row.append(input, name, count);
    target.append(row);
  }
}

function calculateLayout() {
  const model = state.model;
  const width = $("#canvas-wrap").clientWidth || 900;
  state.worldWidth = Math.max(1800, width * 2.15);
  const maxDepth = Math.max(0, ...model.nodes.map((node) => node.depth));
  state.worldHeight = Math.max(760, 210 + (maxDepth + 1) * 155);
  const duration = durationNumber(model.minTimestampNs, model.maxTimestampNs);
  state.positions.clear();

  for (const node of model.nodes) {
    let x;
    if (node.timeOffsetNs !== null && node.timeOffsetNs !== undefined && duration > 0) {
      x = 145 + (Number(node.timeOffsetNs) / duration) * (state.worldWidth - 260);
    } else if (duration === 0 && node.timeOffsetNs !== null) {
      x = state.worldWidth / 2;
    } else {
      x = state.worldWidth - 70;
    }
    const equalLane = Math.min(node.equalTimeOrder, 8) * 5;
    const y = node.kind === "process"
      ? 105 + node.depth * 155 + equalLane
      : 174 + node.depth * 155 + (node.order % 4) * 16 + equalLane;
    const radius = node.kind === "activity" ? Math.min(15, 5 + Math.log2(node.count + 1) * 2.2) : 0;
    state.positions.set(node.id, {
      x, y, radius,
      width: node.kind === "process" ? 154 : radius * 2,
      height: node.kind === "process" ? 45 : radius * 2,
    });
  }
}

function applyFilters() {
  if (!state.model) return;
  const query = state.search.toLowerCase();
  state.visible = state.model.nodes.filter((node) => {
    if (!state.categories.has(node.category)) return false;
    if (node.category === "socket" && state.transport !== "all" && node.transport !== state.transport) return false;
    if (node.category === "socket" && state.direction !== "all" && node.direction !== state.direction) return false;
    if (query) {
      const haystack = [node.label, node.sublabel, node.target, node.processName, node.operation, String(node.pid)]
        .filter(Boolean).join(" ").toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });
  $("#empty-state").hidden = state.visible.length !== 0;
  draw();
}

function resizeCanvas() {
  const rect = canvas.getBoundingClientRect();
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  const width = Math.max(1, Math.round(rect.width * ratio));
  const height = Math.max(1, Math.round(rect.height * ratio));
  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
  }
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
}

function draw() {
  if (!state.model) return;
  resizeCanvas();
  const rect = canvas.getBoundingClientRect();
  context.clearRect(0, 0, rect.width, rect.height);
  context.save();
  context.translate(state.panX, state.panY);
  context.scale(state.zoom, state.zoom);
  drawGrid();

  const visibleIds = new Set(state.visible.map((node) => node.id));
  for (const edge of state.model.edges) {
    if (!visibleIds.has(edge.source) || !visibleIds.has(edge.target)) continue;
    drawEdge(edge);
  }
  for (const node of state.visible) drawNode(node);
  context.restore();
}

function drawGrid() {
  context.save();
  context.lineWidth = 1 / state.zoom;
  context.strokeStyle = "rgba(81, 118, 108, .16)";
  context.fillStyle = "#69837c";
  context.font = `${10 / state.zoom}px ui-monospace, SFMono-Regular, Menlo, monospace`;
  const ticks = 8;
  for (let index = 0; index <= ticks; index += 1) {
    const x = 145 + (index / ticks) * (state.worldWidth - 260);
    context.beginPath();
    context.moveTo(x, 65);
    context.lineTo(x, state.worldHeight);
    context.stroke();
    const duration = durationNumber(state.model.minTimestampNs, state.model.maxTimestampNs);
    const label = formatOffset((duration * index) / ticks);
    context.fillText(label, x + 5 / state.zoom, 58);
  }
  const maxDepth = Math.max(0, ...state.model.nodes.map((node) => node.depth));
  for (let depth = 0; depth <= maxDepth; depth += 1) {
    const y = 105 + depth * 155;
    context.strokeStyle = "rgba(81, 118, 108, .11)";
    context.beginPath();
    context.moveTo(80, y);
    context.lineTo(state.worldWidth - 70, y);
    context.stroke();
    context.fillStyle = "#526c65";
    context.fillText(`depth ${depth}`, 82, y - 12 / state.zoom);
  }
  context.restore();
}

function drawEdge(edge) {
  const source = state.positions.get(edge.source);
  const target = state.positions.get(edge.target);
  if (!source || !target) return;
  context.save();
  const isProcess = edge.kind !== "activity";
  context.strokeStyle = isProcess ? "rgba(185, 245, 106, .48)" : "rgba(109, 214, 232, .18)";
  context.lineWidth = (isProcess ? 1.35 : .8) / state.zoom;
  if (edge.kind === "exec") context.setLineDash([5 / state.zoom, 4 / state.zoom]);
  context.beginPath();
  context.moveTo(source.x, source.y + source.height / 2);
  const midY = (source.y + target.y) / 2;
  context.bezierCurveTo(source.x, midY, target.x, midY, target.x, target.y - target.height / 2);
  context.stroke();
  context.restore();
}

function drawNode(node) {
  const position = state.positions.get(node.id);
  if (!position) return;
  const selected = state.selected === node.id;
  context.save();
  if (node.kind === "process") drawProcessNode(node, position, selected);
  else drawActivityNode(node, position, selected);
  context.restore();
}

function drawProcessNode(node, position, selected) {
  const x = position.x - position.width / 2;
  const y = position.y - position.height / 2;
  roundedRect(x, y, position.width, position.height, 7);
  context.fillStyle = selected ? "rgba(185, 245, 106, .18)" : "rgba(17, 36, 32, .96)";
  context.fill();
  context.lineWidth = (selected ? 2.3 : 1.2) / state.zoom;
  context.strokeStyle = selected ? "#b9f56a" : node.processKind === "observed" ? "#779088" : "#d8eee6";
  context.stroke();
  context.fillStyle = "#edf7f2";
  context.font = "600 11px ui-sans-serif, system-ui, sans-serif";
  context.fillText(ellipsis(node.label, 20), x + 10, y + 18);
  context.fillStyle = "#78928a";
  context.font = "9px ui-monospace, SFMono-Regular, Menlo, monospace";
  context.fillText(ellipsis(`pid ${node.pid} · ${node.processKind}`, 27), x + 10, y + 34);
}

function drawActivityNode(node, position, selected) {
  const color = COLORS[node.category] || COLORS.other;
  context.beginPath();
  context.arc(position.x, position.y, position.radius + (selected ? 3 / state.zoom : 0), 0, Math.PI * 2);
  context.fillStyle = color;
  context.globalAlpha = selected ? 1 : .84;
  context.fill();
  context.globalAlpha = 1;
  if (selected) {
    context.lineWidth = 2 / state.zoom;
    context.strokeStyle = "#ffffff";
    context.stroke();
  }
  if (state.zoom >= .72 || selected) {
    context.fillStyle = "#c9d9d4";
    context.font = `${Math.max(8, 9 / Math.max(.8, state.zoom))}px ui-monospace, SFMono-Regular, Menlo, monospace`;
    context.fillText(ellipsis(node.label, 32), position.x + position.radius + 5 / state.zoom, position.y + 3 / state.zoom);
  }
}

function roundedRect(x, y, width, height, radius) {
  context.beginPath();
  context.roundRect(x, y, width, height, radius);
}

function fitGraph() {
  if (!state.visible.length) return draw();
  const rect = canvas.getBoundingClientRect();
  const points = state.visible.map((node) => state.positions.get(node.id)).filter(Boolean);
  const minX = Math.min(...points.map((point) => point.x - point.width / 2)) - 55;
  const maxX = Math.max(...points.map((point) => point.x + point.width / 2)) + 55;
  const minY = Math.min(...points.map((point) => point.y - point.height / 2)) - 70;
  const maxY = Math.max(...points.map((point) => point.y + point.height / 2)) + 70;
  state.zoom = Math.max(.12, Math.min(1.35, Math.min(rect.width / (maxX - minX), rect.height / (maxY - minY))));
  state.panX = (rect.width - (minX + maxX) * state.zoom) / 2;
  state.panY = (rect.height - (minY + maxY) * state.zoom) / 2;
  draw();
}

function zoomBy(factor, centerX = canvas.clientWidth / 2, centerY = canvas.clientHeight / 2) {
  const previous = state.zoom;
  state.zoom = Math.max(.1, Math.min(5, state.zoom * factor));
  const worldX = (centerX - state.panX) / previous;
  const worldY = (centerY - state.panY) / previous;
  state.panX = centerX - worldX * state.zoom;
  state.panY = centerY - worldY * state.zoom;
  draw();
}

function hitTest(screenX, screenY) {
  const x = (screenX - state.panX) / state.zoom;
  const y = (screenY - state.panY) / state.zoom;
  for (let index = state.visible.length - 1; index >= 0; index -= 1) {
    const node = state.visible[index];
    const point = state.positions.get(node.id);
    if (node.kind === "process") {
      if (Math.abs(x - point.x) <= point.width / 2 && Math.abs(y - point.y) <= point.height / 2) return node;
    } else if (Math.hypot(x - point.x, y - point.y) <= point.radius + 5 / state.zoom) {
      return node;
    }
  }
  return null;
}

function inspectNode(node) {
  state.selected = node.id;
  shell.classList.add("details-open");
  $("#details-title").textContent = node.label;
  const body = $("#details-body");
  body.replaceChildren();
  const fields = [
    ["Kind", node.kind === "process" ? node.processKind : node.category],
    ["Operation", node.operation],
    ["Process", `${node.processName || "unknown"} (pid ${node.pid})`],
    ["Timestamp ns", node.timestampNs || "unavailable"],
    ["Target", node.target || "unavailable"],
    ["Transport", node.transport],
    ["Direction", node.direction],
    ["Events", formatCount(node.eventIds.length)],
  ];
  body.append(detailGrid(fields));
  if (node.eventIds.length) {
    body.append(sectionTitle("Underlying Tracee events"));
    const list = document.createElement("div");
    list.className = "event-list";
    body.append(list);
    appendNodeEventButtons(node, list, 0);
  } else {
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "This observed-process anchor is derived from process context; its non-exec events remain attached as activity nodes.";
    body.append(note);
  }
  draw();
}

function appendNodeEventButtons(node, list, offset) {
  const end = Math.min(node.eventIds.length, offset + 50);
  for (let index = offset; index < end; index += 1) {
    list.append(eventIdButton(node.eventIds[index], `event ${index + 1}`, node.operation));
  }
  const existing = $("#details-body .load-more");
  if (existing) existing.remove();
  if (end < node.eventIds.length) {
    const more = document.createElement("button");
    more.type = "button";
    more.className = "load-more";
    more.textContent = `Show 50 more (${formatCount(node.eventIds.length - end)} remaining)`;
    more.addEventListener("click", () => appendNodeEventButtons(node, list, end));
    $("#details-body").append(more);
  }
}

async function inspectEvent(seq) {
  const response = await fetch(`/api/event?seq=${seq}`);
  if (!response.ok) return;
  const event = await response.json();
  shell.classList.add("details-open");
  $("#details-title").textContent = `#${event.seq} · ${event.name}`;
  const body = $("#details-body");
  body.replaceChildren();
  body.append(detailGrid([
    ["Classification", `${event.category} / ${event.operation}`],
    ["Process", `${event.processName || "unknown"} (pid ${event.pid})`],
    ["Entity", event.processEntityId || "unavailable"],
    ["Timestamp ns", event.timestampNs || "unavailable"],
    ["Source", `line ${event.sourceLine}, item ${event.sourceIndex}`],
    ["Target", event.target || "unavailable"],
    ["FD", event.fd === null ? "unavailable" : String(event.fd)],
    ["Bytes", event.bytes === null ? "unavailable" : String(event.bytes)],
    ["Transport", event.transport],
    ["Direction", event.direction],
    ["Return", event.returnValue === null ? "unavailable" : String(event.returnValue)],
  ]));
  if (event.notes.length) {
    body.append(sectionTitle("Normalization notes"));
    const notes = document.createElement("ul");
    notes.className = "muted";
    for (const value of event.notes) {
      const item = document.createElement("li");
      item.textContent = value;
      notes.append(item);
    }
    body.append(notes);
  }
  body.append(sectionTitle("Original Tracee JSON"));
  const raw = document.createElement("pre");
  raw.className = "raw-event";
  raw.textContent = JSON.stringify(event.raw, null, 2);
  body.append(raw);
}

async function browseEvents(offset = 0) {
  const response = await fetch(`/api/events?offset=${offset}&limit=100`);
  if (!response.ok) return;
  const page = await response.json();
  shell.classList.add("details-open");
  $("#details-title").textContent = "All events";
  const body = $("#details-body");
  body.replaceChildren();
  const summary = document.createElement("p");
  summary.className = "muted";
  summary.textContent = `Chronological events ${formatCount(page.offset + 1)}–${formatCount(Math.min(page.total, page.offset + page.events.length))} of ${formatCount(page.total)}. Equal timestamps retain source sequence order.`;
  body.append(summary);
  const list = document.createElement("div");
  list.className = "event-list";
  for (const event of page.events) {
    list.append(eventIdButton(event.seq, event.name, `${event.processName || "unknown"} · ${event.operation}`));
  }
  body.append(list);
  if (page.offset + page.events.length < page.total) {
    const next = document.createElement("button");
    next.type = "button";
    next.className = "load-more";
    next.textContent = "Next 100 events";
    next.addEventListener("click", () => browseEvents(page.offset + page.events.length));
    body.append(next);
  }
  if (page.offset > 0) {
    const previous = document.createElement("button");
    previous.type = "button";
    previous.className = "load-more";
    previous.textContent = "Previous 100 events";
    previous.addEventListener("click", () => browseEvents(Math.max(0, page.offset - 100)));
    body.append(previous);
  }
}

function eventIdButton(seq, label, detail) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "event-button";
  const code = document.createElement("code");
  code.textContent = `#${seq}`;
  const name = document.createElement("span");
  name.textContent = label;
  const small = document.createElement("small");
  small.textContent = detail;
  button.append(code, name, small);
  button.addEventListener("click", () => inspectEvent(seq));
  return button;
}

function detailGrid(fields) {
  const list = document.createElement("dl");
  list.className = "detail-grid";
  for (const [label, value] of fields) {
    const term = document.createElement("dt");
    term.textContent = label;
    const description = document.createElement("dd");
    description.textContent = value ?? "unavailable";
    list.append(term, description);
  }
  return list;
}

function sectionTitle(value) {
  const heading = document.createElement("h3");
  heading.className = "detail-section";
  heading.textContent = value;
  return heading;
}

function formatCount(value) { return new Intl.NumberFormat().format(value || 0); }
function formatIso(value) { try { return new Date(value).toLocaleString(); } catch { return value; } }
function shortSource(value) { return value.split(/[\\/]/).slice(-2).join("/"); }
function ellipsis(value, max) { return value.length > max ? `${value.slice(0, max - 1)}…` : value; }

function durationNumber(minimum, maximum) {
  if (minimum === null || maximum === null) return 0;
  try { return Number(BigInt(maximum) - BigInt(minimum)); } catch { return 0; }
}

function formatDuration(minimum, maximum) { return formatOffset(durationNumber(minimum, maximum)); }
function formatOffset(ns) {
  if (!Number.isFinite(ns)) return "unknown";
  if (ns >= 1e9) return `${(ns / 1e9).toFixed(ns >= 10e9 ? 1 : 2)}s`;
  if (ns >= 1e6) return `${(ns / 1e6).toFixed(ns >= 10e6 ? 1 : 2)}ms`;
  if (ns >= 1e3) return `${(ns / 1e3).toFixed(1)}µs`;
  return `${Math.round(ns)}ns`;
}

canvas.addEventListener("pointerdown", (event) => {
  canvas.setPointerCapture(event.pointerId);
  state.dragging = true;
  state.dragStart = { x: event.clientX - state.panX, y: event.clientY - state.panY };
  state.pointerStart = { x: event.clientX, y: event.clientY };
  canvas.classList.add("dragging");
});

canvas.addEventListener("pointermove", (event) => {
  if (!state.dragging) return;
  state.panX = event.clientX - state.dragStart.x;
  state.panY = event.clientY - state.dragStart.y;
  draw();
});

canvas.addEventListener("pointerup", (event) => {
  if (!state.dragging) return;
  state.dragging = false;
  canvas.classList.remove("dragging");
  const distance = Math.hypot(event.clientX - state.pointerStart.x, event.clientY - state.pointerStart.y);
  if (distance < 5) {
    const rect = canvas.getBoundingClientRect();
    const node = hitTest(event.clientX - rect.left, event.clientY - rect.top);
    if (node) inspectNode(node);
  }
});

canvas.addEventListener("wheel", (event) => {
  event.preventDefault();
  const rect = canvas.getBoundingClientRect();
  zoomBy(event.deltaY < 0 ? 1.12 : .89, event.clientX - rect.left, event.clientY - rect.top);
}, { passive: false });

canvas.addEventListener("keydown", (event) => {
  if (event.key === "+" || event.key === "=") zoomBy(1.2);
  if (event.key === "-") zoomBy(.82);
  if (event.key === "0") fitGraph();
});

$("#fit").addEventListener("click", fitGraph);
$("#zoom-in").addEventListener("click", () => zoomBy(1.25));
$("#zoom-out").addEventListener("click", () => zoomBy(.8));
$("#all-events").addEventListener("click", () => browseEvents(0));
$("#close-details").addEventListener("click", () => {
  shell.classList.remove("details-open");
  state.selected = null;
  draw();
});
$("#bucket").addEventListener("change", () => loadGraph({ preserveView: true }));
$("#group").addEventListener("change", () => loadGraph({ preserveView: true }));
$("#transport").addEventListener("change", (event) => { state.transport = event.target.value; applyFilters(); });
$("#direction").addEventListener("change", (event) => { state.direction = event.target.value; applyFilters(); });
$("#search").addEventListener("input", (event) => { state.search = event.target.value.trim(); applyFilters(); });

new ResizeObserver(() => {
  if (!state.model) return;
  calculateLayout();
  draw();
}).observe($("#canvas-wrap"));

loadGraph();
