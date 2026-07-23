"use strict";

const $ = (selector) => document.querySelector(selector);
const canvas = $("#graph");
const context = canvas.getContext("2d");
const shell = $(".app-shell");
const canvasWrap = $("#canvas-wrap");
const scrollSpacer = $("#scroll-spacer");
const VIEWER = Object.freeze(window.SKILLSISSUE_VIEWER || { mode: "server" });
let staticSnapshotPromise = null;
let staticEventMap = null;
const staticEventPagePromises = new Map();

const LAYOUT = {
  rowHeight: 88,
  top: 70,
  bottom: 76,
  nodeWidth: 196,
  nodeHeight: 64,
  timelineGutter: 88,
  rightPadding: 34,
};

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
  layoutNodes: [],
  layoutCompacted: false,
  visibleIds: new Set(),
  nodeById: new Map(),
  zoom: 1,
  panX: 0,
  worldHeight: 900,
  maxDepth: 0,
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
    state.model = await graphPayload(bucket, group);
    renderHeader();
    renderStats();
    renderCategoryFilters();
    applyFilters({ resetLayout: true });
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

function staticRunId() {
  const runId = new URLSearchParams(window.location.search).get("run") || "";
  if (!/^run_[0-9a-f]+$/.test(runId)) {
    throw new Error("This graph link is missing a valid run identifier.");
  }
  return runId;
}

async function staticSnapshot() {
  if (staticSnapshotPromise) return staticSnapshotPromise;
  staticSnapshotPromise = (async () => {
    const root = String(VIEWER.dataRoot || "../runs").replace(/\/$/, "");
    const response = await fetch(`${root}/${encodeURIComponent(staticRunId())}/graph.json`);
    if (!response.ok) throw new Error(`published trace request failed (${response.status})`);
    const snapshot = await response.json();
    staticEventMap = new Map();
    return snapshot;
  })();
  return staticSnapshotPromise;
}

async function staticEventPage(page) {
  if (staticEventPagePromises.has(page)) return staticEventPagePromises.get(page);
  const promise = (async () => {
    const snapshot = await staticSnapshot();
    const root = String(VIEWER.dataRoot || "../runs").replace(/\/$/, "");
    const response = await fetch(`${root}/${encodeURIComponent(staticRunId())}/events/${page}.json`);
    if (!response.ok) throw new Error(`published event page request failed (${response.status})`);
    const events = await response.json();
    for (const event of events) staticEventMap.set(String(event.seq), event);
    return { events, total: snapshot.eventCount, pageSize: snapshot.eventPageSize };
  })();
  staticEventPagePromises.set(page, promise);
  return promise;
}

async function graphPayload(bucket, group) {
  if (VIEWER.mode === "static") return (await staticSnapshot()).graph;
  const response = await fetch(`./api/graph?bucket_ns=${bucket}&group=${group}`);
  if (!response.ok) throw new Error(`graph request failed (${response.status})`);
  return response.json();
}

async function eventSelection(ids) {
  if (VIEWER.mode === "static") {
    const snapshot = await staticSnapshot();
    const pages = [...new Set(ids.map((id) => Math.floor((Number(id) - 1) / snapshot.eventPageSize)))];
    await Promise.all(pages.map(staticEventPage));
    return ids.map((id) => staticEventMap.get(String(id))).filter(Boolean);
  }
  const response = await fetch(`./api/events?ids=${ids.join(",")}`);
  if (!response.ok) throw new Error(`event detail request failed (${response.status})`);
  return (await response.json()).events || [];
}

async function eventBySequence(seq) {
  if (VIEWER.mode === "static") {
    const snapshot = await staticSnapshot();
    await staticEventPage(Math.floor((Number(seq) - 1) / snapshot.eventPageSize));
    return staticEventMap.get(String(seq)) || null;
  }
  const response = await fetch(`./api/event?seq=${seq}`);
  if (!response.ok) return null;
  return response.json();
}

async function eventPage(offset, limit) {
  if (VIEWER.mode === "static") {
    const snapshot = await staticSnapshot();
    const firstPage = Math.floor(offset / snapshot.eventPageSize);
    const lastPage = Math.floor((Math.max(offset, offset + limit - 1)) / snapshot.eventPageSize);
    const pages = await Promise.all(
      Array.from({ length: lastPage - firstPage + 1 }, (_, index) => staticEventPage(firstPage + index)),
    );
    const events = pages.flatMap((page) => page.events);
    const start = offset - firstPage * snapshot.eventPageSize;
    return { offset, limit, total: snapshot.eventCount, events: events.slice(start, start + limit) };
  }
  const response = await fetch(`./api/events?offset=${offset}&limit=${limit}`);
  if (!response.ok) return null;
  return response.json();
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

function calculateLayout(nodes = state.layoutCompacted ? state.layoutNodes : state.model.nodes) {
  const model = state.model;
  const width = canvasWrap.clientWidth || 900;
  state.maxDepth = Math.max(0, ...model.nodes.map((node) => node.depth));
  state.layoutNodes = nodes;
  state.worldHeight = Math.max(
    canvasWrap.clientHeight || 640,
    LAYOUT.top + Math.max(0, nodes.length - 1) * LAYOUT.rowHeight + LAYOUT.bottom,
  );
  state.positions.clear();
  state.nodeById = new Map(model.nodes.map((node) => [node.id, node]));

  const left = LAYOUT.timelineGutter + LAYOUT.nodeWidth / 2 + 16;
  const right = Math.max(left, width - LAYOUT.rightPadding - LAYOUT.nodeWidth / 2);
  const laneWidth = Math.max(0, right - left);

  nodes.forEach((node, index) => {
    const depthRatio = state.maxDepth === 0 ? .5 : node.depth / state.maxDepth;
    state.positions.set(node.id, {
      x: left + laneWidth * depthRatio,
      y: LAYOUT.top + index * LAYOUT.rowHeight,
      width: LAYOUT.nodeWidth,
      height: LAYOUT.nodeHeight,
      row: index,
    });
  });
  updateScrollExtent();
}

function applyFilters({ resetLayout = true } = {}) {
  if (!state.model) return;
  const query = state.search.toLowerCase();
  state.visible = state.model.nodes.filter((node) => {
    if (!state.categories.has(node.category)) return false;
    if (node.category === "socket" && state.transport !== "all" && node.transport !== state.transport) return false;
    if (node.category === "socket" && state.direction !== "all" && node.direction !== state.direction) return false;
    if (query) {
      const haystack = [node.label, node.sublabel, node.command, node.target, node.processName, node.operation, String(node.pid)]
        .filter(Boolean).join(" ").toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });
  state.visibleIds = new Set(state.visible.map((node) => node.id));
  if (resetLayout) {
    state.layoutCompacted = false;
    calculateLayout(state.model.nodes);
    $("#filter-layout-note").textContent = `${formatCount(state.visible.length)} visible nodes. Refresh removes empty rows.`;
  }
  $("#empty-state").hidden = state.visible.length !== 0;
  draw();
}

function refreshFilteredLayout() {
  state.layoutCompacted = true;
  calculateLayout([...state.visible]);
  canvasWrap.scrollTop = 0;
  $("#filter-layout-note").textContent = `${formatCount(state.visible.length)} visible nodes packed chronologically.`;
  draw();
}

function updateScrollExtent() {
  const viewportHeight = Math.max(1, canvasWrap.clientHeight);
  const scaledHeight = Math.max(viewportHeight, state.worldHeight * state.zoom);
  scrollSpacer.style.height = `${Math.max(1, scaledHeight - viewportHeight)}px`;
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
  const view = visibleWorldRange(rect.height);
  drawTimelineRows(rect, view);

  context.save();
  context.translate(horizontalTranslation(rect.width), -canvasWrap.scrollTop);
  context.scale(state.zoom, state.zoom);
  for (const edge of state.model.edges) {
    if (!state.visibleIds.has(edge.source) || !state.visibleIds.has(edge.target)) continue;
    const source = state.positions.get(edge.source);
    const target = state.positions.get(edge.target);
    if (!source || !target || !verticalSpanIsVisible(source.y, target.y, view)) continue;
    drawEdge(edge);
  }
  for (const node of state.visible) {
    const position = state.positions.get(node.id);
    if (position && position.y >= view.start && position.y <= view.end) drawNode(node);
  }
  context.restore();
  drawDepthHeader(rect);
}

function visibleWorldRange(viewportHeight) {
  const buffer = LAYOUT.rowHeight * 2;
  return {
    start: Math.max(0, canvasWrap.scrollTop / state.zoom - buffer),
    end: (canvasWrap.scrollTop + viewportHeight) / state.zoom + buffer,
  };
}

function verticalSpanIsVisible(sourceY, targetY, view) {
  return Math.max(sourceY, targetY) >= view.start && Math.min(sourceY, targetY) <= view.end;
}

function horizontalTranslation(viewportWidth) {
  return state.panX + (viewportWidth / 2) * (1 - state.zoom);
}

function screenX(worldX, viewportWidth) {
  return horizontalTranslation(viewportWidth) + worldX * state.zoom;
}

function drawTimelineRows(rect, view) {
  context.save();
  context.lineWidth = 1;
  context.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
  const firstRow = Math.max(0, Math.floor((view.start - LAYOUT.top) / LAYOUT.rowHeight));
  const lastRow = Math.min(
    state.layoutNodes.length - 1,
    Math.ceil((view.end - LAYOUT.top) / LAYOUT.rowHeight),
  );

  for (let index = firstRow; index <= lastRow; index += 1) {
    const node = state.layoutNodes[index];
    const position = state.positions.get(node.id);
    const y = position.y * state.zoom - canvasWrap.scrollTop;
    context.strokeStyle = "rgba(81, 118, 108, .17)";
    context.beginPath();
    context.moveTo(LAYOUT.timelineGutter, y);
    context.lineTo(rect.width, y);
    context.stroke();
    context.fillStyle = state.visibleIds.has(node.id) ? "#78928a" : "#405751";
    context.fillText(formatNodeTime(node), 9, y + 3);
  }

  const depthPositions = depthScreenPositions(rect.width);
  for (const { x } of depthPositions) {
    context.strokeStyle = "rgba(81, 118, 108, .09)";
    context.beginPath();
    context.moveTo(x, 0);
    context.lineTo(x, rect.height);
    context.stroke();
  }
  context.restore();
}

function drawDepthHeader(rect) {
  context.save();
  context.fillStyle = "rgba(7, 16, 15, .94)";
  context.fillRect(0, 0, rect.width, 29);
  context.strokeStyle = "rgba(81, 118, 108, .22)";
  context.beginPath();
  context.moveTo(0, 28.5);
  context.lineTo(rect.width, 28.5);
  context.stroke();
  context.fillStyle = "#69837c";
  context.font = "9px ui-monospace, SFMono-Regular, Menlo, monospace";
  context.fillText("time", 9, 18);
  const compactLabels = rect.width < 760;
  let previousLabelX = -Infinity;
  depthScreenPositions(rect.width).forEach(({ depth, x }) => {
    const minimumGap = compactLabels ? 34 : 52;
    if (x - previousLabelX < minimumGap) return;
    const label = compactLabels ? `d${depth}` : `depth ${depth}`;
    context.fillText(label, x - (compactLabels ? 7 : 20), 18);
    previousLabelX = x;
  });
  context.restore();
}

function depthScreenPositions(viewportWidth) {
  const positions = [];
  if (!state.layoutNodes.length) return positions;
  const representative = new Map();
  for (const node of state.layoutNodes) {
    if (!representative.has(node.depth)) representative.set(node.depth, node.id);
  }
  for (let depth = 0; depth <= state.maxDepth; depth += 1) {
    const id = representative.get(depth);
    if (id) positions.push({ depth, x: screenX(state.positions.get(id).x, viewportWidth) });
  }
  return positions;
}

function formatNodeTime(node) {
  if (node.timeOffsetNs === null || node.timeOffsetNs === undefined) return "no time";
  return formatOffset(Number(node.timeOffsetNs));
}

function drawEdge(edge) {
  const source = state.positions.get(edge.source);
  const target = state.positions.get(edge.target);
  if (!source || !target) return;
  context.save();
  const isProcess = edge.kind !== "activity";
  context.strokeStyle = isProcess ? "rgba(185, 245, 106, .52)" : "rgba(109, 214, 232, .30)";
  context.fillStyle = context.strokeStyle;
  context.lineWidth = (isProcess ? 1.45 : 1.05) / state.zoom;
  if (edge.kind === "exec") context.setLineDash([5 / state.zoom, 4 / state.zoom]);
  const sourceBottom = source.y + source.height / 2;
  const targetTop = target.y - target.height / 2;
  const bendY = Math.min(targetTop - 8, sourceBottom + Math.max(12, (targetTop - sourceBottom) * .42));
  context.beginPath();
  context.moveTo(source.x, sourceBottom);
  context.lineTo(source.x, bendY);
  context.lineTo(target.x, bendY);
  context.lineTo(target.x, targetTop - 6 / state.zoom);
  context.stroke();
  context.setLineDash([]);
  const arrow = 5 / state.zoom;
  context.beginPath();
  context.moveTo(target.x, targetTop);
  context.lineTo(target.x - arrow, targetTop - arrow * 1.5);
  context.lineTo(target.x + arrow, targetTop - arrow * 1.5);
  context.closePath();
  context.fill();
  context.restore();
}

function drawNode(node) {
  const position = state.positions.get(node.id);
  if (!position) return;
  const selected = state.selected === node.id;
  context.save();
  drawEventNode(node, position, selected);
  context.restore();
}

function drawEventNode(node, position, selected) {
  const x = position.x - position.width / 2;
  const y = position.y - position.height / 2;
  roundedRect(x, y, position.width, position.height, 7);
  context.fillStyle = selected ? "rgba(101, 229, 194, .17)" : "rgba(17, 36, 32, .97)";
  context.fill();
  context.lineWidth = (selected ? 2.3 : 1.2) / state.zoom;
  const color = COLORS[node.category] || COLORS.other;
  context.strokeStyle = selected ? "#ffffff" : color;
  context.stroke();
  context.fillStyle = color;
  context.fillRect(x, y, 4 / state.zoom, position.height);
  context.fillStyle = "#edf7f2";
  context.font = "600 11px ui-sans-serif, system-ui, sans-serif";
  context.fillText(ellipsis(node.label, 28), x + 11, y + 17);
  context.fillStyle = "#78928a";
  context.font = "9px ui-monospace, SFMono-Regular, Menlo, monospace";
  const primary = node.command || node.sublabel || node.target || "details unavailable";
  context.fillText(ellipsis(primary, 34), x + 11, y + 35);
  context.fillStyle = "#607c74";
  context.font = "8px ui-monospace, SFMono-Regular, Menlo, monospace";
  context.fillText(ellipsis(nodeMetadata(node), 40), x + 11, y + 52);
}

function nodeMetadata(node) {
  if (node.kind === "process") return `pid ${node.pid} · ${node.processKind}`;
  const parts = [];
  if (node.category === "socket") {
    parts.push(node.transport === "not-applicable" ? "transport n/a" : node.transport.toUpperCase());
    parts.push(formatDirection(node.direction));
  } else {
    parts.push(node.operation);
  }
  if (node.byteCount) parts.push(formatBytes(node.byteCount));
  if (node.fileDescriptors?.length) parts.push(`fd ${node.fileDescriptors.join(",")}`);
  parts.push(`${node.count} event${node.count === 1 ? "" : "s"}`);
  if (node.failureCount) parts.push(`${node.failureCount} failed`);
  return parts.join(" · ");
}

function roundedRect(x, y, width, height, radius) {
  context.beginPath();
  context.roundRect(x, y, width, height, radius);
}

function fitGraph() {
  state.zoom = 1;
  state.panX = 0;
  updateScrollExtent();
  canvasWrap.scrollTop = 0;
  draw();
}

function zoomBy(factor, centerX = canvas.clientWidth / 2, centerY = canvas.clientHeight / 2) {
  const previous = state.zoom;
  const next = Math.max(1, Math.min(4, state.zoom * factor));
  if (next === previous) return;
  const viewportWidth = canvas.clientWidth;
  const previousTranslation = horizontalTranslation(viewportWidth);
  const worldX = (centerX - previousTranslation) / previous;
  const worldY = (centerY + canvasWrap.scrollTop) / previous;
  state.zoom = next;
  state.panX = centerX - worldX * next - (viewportWidth / 2) * (1 - next);
  clampPanX(viewportWidth);
  updateScrollExtent();
  canvasWrap.scrollTop = Math.max(0, worldY * next - centerY);
  draw();
}

function clampPanX(viewportWidth = canvas.clientWidth) {
  const maxPan = Math.max(0, viewportWidth * (state.zoom - 1) / 2);
  state.panX = Math.max(-maxPan, Math.min(maxPan, state.panX));
}

function hitTest(screenX, screenY) {
  const x = (screenX - horizontalTranslation(canvas.clientWidth)) / state.zoom;
  const y = (screenY + canvasWrap.scrollTop) / state.zoom;
  for (let index = state.visible.length - 1; index >= 0; index -= 1) {
    const node = state.visible[index];
    const point = state.positions.get(node.id);
    if (Math.abs(x - point.x) <= point.width / 2 && Math.abs(y - point.y) <= point.height / 2) return node;
  }
  return null;
}

async function inspectNode(node) {
  state.selected = node.id;
  shell.classList.add("details-open");
  $("#details-title").textContent = node.label;
  const body = $("#details-body");
  body.replaceChildren();
  const fields = [
    ["Kind", node.kind === "process" ? node.processKind : node.category],
    ["Operation", node.operation],
    ["Process", `${node.processName || "unknown"} (pid ${node.pid})`],
    ["Process identity", node.processKey],
    ["Execution depth", String(node.depth)],
    ["Command", node.command || "not captured for this node"],
    ["Timestamp ns", node.timestampNs || "unavailable"],
    ["Relative time", formatNodeTime(node)],
    ["Target", node.target || "unavailable"],
    ["Transport", node.transport],
    ["Direction", formatDirection(node.direction)],
    ["File descriptors", node.fileDescriptors?.length ? node.fileDescriptors.join(", ") : "unavailable"],
    ["Transferred bytes", node.byteCount ? formatBytes(node.byteCount) : "unavailable"],
    ["Results", formatOutcomes(node.successCount, node.failureCount, node.count)],
    ["Events", formatCount(node.eventIds.length)],
  ];
  body.append(detailGrid(fields));
  if (!node.eventIds.length) {
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "This observed-process anchor is derived from process context; its non-exec events remain attached as activity nodes.";
    body.append(note);
    draw();
    return;
  }

  const loading = document.createElement("p");
  loading.className = "muted";
  loading.textContent = "Loading normalized arguments and raw Tracee evidence…";
  body.append(loading);
  draw();

  const ids = node.eventIds.slice(0, 100);
  try {
    const events = await eventSelection(ids);
    if (state.selected !== node.id) return;
    loading.remove();
    body.append(sectionTitle("Aggregate evidence"));
    body.append(detailGrid(aggregateEventFields(events)));
    appendCategoryEvidence(node, events, body);
    body.append(sectionTitle("Underlying Tracee events"));
    const list = document.createElement("div");
    list.className = "event-list";
    body.append(list);
    appendNodeEventButtons(node, list, 0, new Map(events.map((event) => [event.seq, event])));
    if (node.eventIds.length > ids.length) {
      const note = document.createElement("p");
      note.className = "muted detail-limit-note";
      note.textContent = `Aggregate evidence summarizes the first ${formatCount(ids.length)} of ${formatCount(node.eventIds.length)} events; every event ID remains available below.`;
      body.append(note);
    }
  } catch (error) {
    loading.textContent = `Could not load detailed event evidence: ${error.message}`;
  }
}

function appendNodeEventButtons(node, list, offset, eventMap = new Map()) {
  const end = Math.min(node.eventIds.length, offset + 50);
  for (let index = offset; index < end; index += 1) {
    const seq = node.eventIds[index];
    const event = eventMap.get(seq);
    list.append(eventIdButton(
      seq,
      event?.name || `event ${index + 1}`,
      event ? eventButtonDetail(event) : node.operation,
    ));
  }
  const existing = $("#details-body .load-more");
  if (existing) existing.remove();
  if (end < node.eventIds.length) {
    const more = document.createElement("button");
    more.type = "button";
    more.className = "load-more";
    more.textContent = `Show 50 more (${formatCount(node.eventIds.length - end)} remaining)`;
    more.addEventListener("click", () => appendNodeEventButtons(node, list, end, eventMap));
    $("#details-body").append(more);
  }
}

async function inspectEvent(seq) {
  const event = await eventBySequence(seq);
  if (!event) return;
  shell.classList.add("details-open");
  $("#details-title").textContent = `#${event.seq} · ${event.name}`;
  const body = $("#details-body");
  body.replaceChildren();
  body.append(detailGrid([
    ["Classification", `${event.category} / ${event.operation}`],
    ["Process", `${event.processName || "unknown"} (pid ${event.pid})`],
    ["Parent PID", event.ppid === null ? "unavailable" : String(event.ppid)],
    ["Entity", event.processEntityId || "unavailable"],
    ["Normalized detail", event.detail || "unavailable"],
    ["Timestamp ns", event.timestampNs || "unavailable"],
    ["Source", `line ${event.sourceLine}, item ${event.sourceIndex}`],
    ["Target", event.target || "unavailable"],
    ["FD", event.fd === null ? "unavailable" : String(event.fd)],
    ["Bytes", event.bytes === null ? "unavailable" : String(event.bytes)],
    ["Transport", event.transport],
    ["Direction", formatDirection(event.direction)],
    ["Success", event.success === null ? "unknown" : String(event.success)],
    ["Return", event.returnValue === null ? "unavailable" : String(event.returnValue)],
  ]));
  appendCategoryEvidence(event, [event], body);
  body.append(sectionTitle("Tracee arguments"));
  body.append(argumentTable(event.args));
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
  const rawDetails = document.createElement("details");
  rawDetails.className = "raw-details";
  const summary = document.createElement("summary");
  summary.textContent = "Original Tracee JSON";
  const raw = document.createElement("pre");
  raw.className = "raw-event";
  raw.textContent = JSON.stringify(event.raw, null, 2);
  rawDetails.append(summary, raw);
  body.append(rawDetails);
}

function aggregateEventFields(events) {
  const names = unique(events.map((event) => event.name));
  const fds = unique(events.map((event) => event.fd).filter((value) => value !== null));
  const targets = unique(events.map((event) => event.target).filter(Boolean));
  const argumentNames = unique(events.flatMap((event) => Object.keys(event.args || {})));
  const requestedBytes = events.reduce((total, event) => total + numericArgument(event.args, "count"), 0);
  const returnedBytes = events.reduce((total, event) => total + (event.bytes || 0), 0);
  const successes = events.filter((event) => event.success === true).length;
  const failures = events.filter((event) => event.success === false).length;
  const sources = events.map((event) => event.sourceLine).filter((value) => value !== undefined);
  return [
    ["Tracee event names", names.join(", ") || "unavailable"],
    ["Targets", summarizeValues(targets)],
    ["File descriptors", fds.join(", ") || "unavailable"],
    ["Requested bytes", requestedBytes ? formatBytes(requestedBytes) : "unavailable"],
    ["Returned bytes", returnedBytes ? formatBytes(returnedBytes) : "unavailable"],
    ["Results", formatOutcomes(successes, failures, events.length)],
    ["Argument fields", argumentNames.join(", ") || "none"],
    ["Source lines", sources.length ? `${Math.min(...sources)}–${Math.max(...sources)}` : "unavailable"],
  ];
}

function appendCategoryEvidence(subject, events, body) {
  if (!events.length) return;
  if (subject.category === "process") appendCommandEvidence(events, body);
  if (subject.category === "file") appendFileEvidence(events, body);
  if (subject.category === "socket") appendSocketEvidence(subject, events, body);
}

function appendCommandEvidence(events, body) {
  const event = events.find((candidate) => argument(candidate.args, "argv") !== undefined);
  if (!event) return;
  body.append(sectionTitle("Process invocation"));
  body.append(detailGrid([
    ["Command", formatCommand(argument(event.args, "argv"))],
    ["Executable", argument(event.args, "cmdpath") || argument(event.args, "pathname") || "unavailable"],
    ["Working directory", argument(event.args, "pwd") || "unavailable"],
    ["Interpreter", argument(event.args, "interpreter_pathname") || argument(event.args, "interp") || "unavailable"],
    ["Standard input", argument(event.args, "stdin_path") || "unavailable"],
    ["Previous image", argument(event.args, "prev_comm") || "unavailable"],
  ]));
}

function appendFileEvidence(events, body) {
  const ioEvents = events.filter((event) => event.operation === "read" || event.operation === "write");
  if (!ioEvents.length) return;
  const pointers = unique(ioEvents.map((event) => argument(event.args, "buf") ?? argument(event.args, "buffer"))
    .filter((value) => typeof value === "string" && /^0x[0-9a-f]+$/i.test(value)));
  const captured = ioEvents.flatMap(capturedContent);
  const requested = ioEvents.reduce((total, event) => total + numericArgument(event.args, "count"), 0);
  const returned = ioEvents.reduce((total, event) => total + (event.bytes || 0), 0);
  body.append(sectionTitle("File I/O evidence"));
  body.append(detailGrid([
    ["Operations", unique(ioEvents.map((event) => event.operation)).join(", ")],
    ["Resolved paths", summarizeValues(unique(ioEvents.map((event) => event.target).filter(Boolean)))],
    ["Requested bytes", requested ? formatBytes(requested) : "unavailable"],
    ["Returned bytes", returned ? formatBytes(returned) : "unavailable"],
    ["Buffer pointers", summarizeValues(pointers)],
    ["Captured content", captured.length ? `${captured.length} payload value(s)` : "not captured in these Tracee records"],
  ]));
  if (captured.length) {
    const contentList = document.createElement("div");
    contentList.className = "content-list";
    for (const item of captured.slice(0, 12)) {
      const content = document.createElement("pre");
      content.className = "content-preview";
      content.textContent = `${item.name}: ${formatArgument(item.value)}`;
      contentList.append(content);
    }
    body.append(contentList);
  } else {
    const note = document.createElement("p");
    note.className = "evidence-note";
    note.textContent = "This capture records buffer addresses and byte counts, not the bytes stored at those addresses. Content cannot be reconstructed from a pointer alone.";
    body.append(note);
  }
}

function appendSocketEvidence(subject, events, body) {
  const families = unique(events.flatMap((event) => nestedValues(event.args, "sa_family")));
  const types = unique(events.map((event) => argument(event.args, "type") ?? argument(event.args, "sock_type")).filter(Boolean));
  const endpoints = unique(events.map((event) => event.target).filter(Boolean));
  body.append(sectionTitle("Socket evidence"));
  body.append(detailGrid([
    ["Transport", subject.transport || "unknown"],
    ["Direction", formatDirection(subject.direction)],
    ["Socket family", summarizeValues(families)],
    ["Socket type", summarizeValues(types)],
    ["Endpoints", summarizeValues(endpoints)],
    ["Transferred bytes", formatBytes(events.reduce((total, event) => total + (event.bytes || 0), 0))],
  ]));
}

function argumentTable(args = {}) {
  const table = document.createElement("dl");
  table.className = "argument-grid";
  const entries = Object.entries(args);
  if (!entries.length) {
    const term = document.createElement("dt");
    term.textContent = "—";
    const value = document.createElement("dd");
    value.textContent = "No arguments were captured.";
    table.append(term, value);
    return table;
  }
  for (const [name, rawValue] of entries) {
    const term = document.createElement("dt");
    term.textContent = name;
    const value = document.createElement("dd");
    value.textContent = formatArgument(rawValue);
    table.append(term, value);
  }
  return table;
}

function capturedContent(event) {
  const values = [];
  for (const [name, value] of Object.entries(event.args || {})) {
    const lower = name.toLowerCase();
    const payloadName = ["content", "data", "payload", "payload_data", "buffer_data"].includes(lower);
    const bufferValue = ["buf", "buffer"].includes(lower)
      && !(typeof value === "string" && /^0x[0-9a-f]+$/i.test(value));
    if (payloadName || bufferValue) values.push({ name, value });
  }
  return values;
}

function argument(args, name) {
  const entry = Object.entries(args || {}).find(([key]) => key.toLowerCase() === name.toLowerCase());
  return entry?.[1];
}

function numericArgument(args, name) {
  const value = Number(argument(args, name));
  return Number.isFinite(value) && value > 0 ? value : 0;
}

function nestedValues(value, key) {
  if (Array.isArray(value)) return value.flatMap((item) => nestedValues(item, key));
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([name, item]) => [
    ...(name.toLowerCase() === key.toLowerCase() ? [String(item)] : []),
    ...nestedValues(item, key),
  ]);
}

async function browseEvents(offset = 0) {
  const page = await eventPage(offset, 100);
  if (!page) return;
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

function eventButtonDetail(event) {
  const parts = [event.processName || `pid ${event.pid}`, event.operation];
  if (event.target) parts.push(event.target);
  if (event.bytes) parts.push(formatBytes(event.bytes));
  return parts.join(" · ");
}

function unique(values) {
  return [...new Set(values.map((value) => String(value)))];
}

function summarizeValues(values) {
  if (!values.length) return "unavailable";
  const visible = values.slice(0, 6);
  return `${visible.join(", ")}${values.length > visible.length ? ` (+${values.length - visible.length} more)` : ""}`;
}

function formatArgument(value) {
  if (value === undefined || value === null) return "unavailable";
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

function formatCommand(value) {
  if (!Array.isArray(value)) return formatArgument(value);
  return value.map((part) => String(part)).join(" ");
}

function formatDirection(value) {
  const labels = {
    outbound: "outbound",
    "inbound-open": "inbound open/listen",
    "inbound-accept": "inbound accept",
    inbound: "inbound receive",
    unknown: "unknown / ambiguous",
    "not-applicable": "not applicable",
  };
  return labels[value] || value || "unknown";
}

function formatOutcomes(successes = 0, failures = 0, total = 0) {
  const unknown = Math.max(0, total - successes - failures);
  const parts = [];
  if (successes) parts.push(`${formatCount(successes)} succeeded`);
  if (failures) parts.push(`${formatCount(failures)} failed`);
  if (unknown) parts.push(`${formatCount(unknown)} unknown`);
  return parts.join(", ") || "unavailable";
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(bytes >= 10 * 1024 ? 1 : 2)} KiB`;
  return `${(bytes / (1024 ** 2)).toFixed(bytes >= 10 * 1024 ** 2 ? 1 : 2)} MiB`;
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
  state.dragStart = {
    x: event.clientX,
    y: event.clientY,
    panX: state.panX,
    scrollTop: canvasWrap.scrollTop,
  };
  state.pointerStart = { x: event.clientX, y: event.clientY };
  canvas.classList.add("dragging");
});

canvas.addEventListener("pointermove", (event) => {
  if (!state.dragging) return;
  state.panX = state.dragStart.panX + event.clientX - state.dragStart.x;
  clampPanX();
  canvasWrap.scrollTop = state.dragStart.scrollTop - (event.clientY - state.dragStart.y);
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
  if (!event.ctrlKey && !event.metaKey) return;
  event.preventDefault();
  const rect = canvas.getBoundingClientRect();
  zoomBy(event.deltaY < 0 ? 1.12 : .89, event.clientX - rect.left, event.clientY - rect.top);
}, { passive: false });

canvas.addEventListener("keydown", (event) => {
  if (event.key === "+" || event.key === "=") zoomBy(1.2);
  if (event.key === "-") zoomBy(.82);
  if (event.key === "0") fitGraph();
});

$("#refresh-layout").addEventListener("click", refreshFilteredLayout);
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
canvasWrap.addEventListener("scroll", draw, { passive: true });

new ResizeObserver(() => {
  if (!state.model) return;
  calculateLayout();
  clampPanX();
  draw();
}).observe(canvasWrap);

if (VIEWER.mode === "static") {
  $("#density-controls").hidden = true;
  const indexLink = $("#index-link");
  indexLink.href = VIEWER.indexUrl || "../";
  indexLink.hidden = false;
}

loadGraph();
