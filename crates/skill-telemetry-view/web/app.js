"use strict";

const $ = (selector) => document.querySelector(selector);
const canvas = $("#graph");
const context = canvas.getContext("2d");
const shell = $(".app-shell");
const canvasWrap = $("#canvas-wrap");
const VIEWER = Object.freeze(window.SKILLSISSUE_VIEWER || { mode: "server" });
let staticSnapshotPromise = null;
let staticEventMap = null;
const staticEventPagePromises = new Map();
let staticNetworkIndexPromise = null;

const LAYOUT = {
  nodeWidth: 196,
  nodeHeight: 64,
  processLinkDistance: 270,
  activityLinkDistance: 205,
  chargeRadius: 440,
  collisionPadding: 24,
  fitPadding: 44,
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
  assessment: null,
  positions: new Map(),
  visible: [],
  layoutNodes: [],
  visibleEdges: [],
  visibleIds: new Set(),
  nodeById: new Map(),
  zoom: 1,
  panX: 0,
  panY: 0,
  simulationAlpha: 0,
  simulationFrame: null,
  simulationTicks: 0,
  categories: new Set(["process", "file", "socket", "fd", "other"]),
  search: "",
  transport: "all",
  direction: "all",
  includePreDetonation: false,
  selected: null,
  activeFinding: null,
  threatNodeIds: new Set(),
  threatEdgeIds: new Set(),
  assessmentOpened: false,
  dragging: false,
  dragNode: null,
  dragStart: null,
  pointerStart: null,
  networkCaptureCount: 0,
};

async function loadGraph({ preserveView = false } = {}) {
  $("#loading").hidden = false;
  const bucket = $("#bucket").value;
  const group = $("#group").value;
  try {
    const snapshot = VIEWER.mode === "static" ? await staticSnapshot() : null;
    state.model = snapshot ? snapshot.graph : await graphPayload(bucket, group);
    state.assessment = snapshot?.assessment || null;
    state.networkCaptureCount = snapshot?.networkCaptureCount || 0;
    renderHeader();
    renderStats();
    renderAssessment();
    renderNetworkControls();
    renderCategoryFilters();
    applyFilters({ resetLayout: true });
    if (!preserveView) fitGraph();
    else draw();
    const requestedView = new URLSearchParams(window.location.search).get("view");
    if (!state.assessmentOpened && requestedView === "findings" && state.assessment) {
      state.assessmentOpened = true;
      inspectAssessment();
    }
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

async function staticNetworkIndex() {
  if (VIEWER.mode !== "static") return { captureCount: 0, captures: [] };
  if (staticNetworkIndexPromise) return staticNetworkIndexPromise;
  staticNetworkIndexPromise = (async () => {
    const root = String(VIEWER.dataRoot || "../runs").replace(/\/$/, "");
    const response = await fetch(`${root}/${encodeURIComponent(staticRunId())}/network/index.json`);
    if (!response.ok) throw new Error(`published network index request failed (${response.status})`);
    return response.json();
  })();
  return staticNetworkIndexPromise;
}

async function staticNetworkDetail(capture) {
  const root = String(VIEWER.dataRoot || "../runs").replace(/\/$/, "");
  const detail = String(capture.detailUrl || "");
  if (!/^network\/[1-9][0-9]*\.json$/.test(detail)) {
    throw new Error("published network detail path is invalid");
  }
  const response = await fetch(
    `${root}/${encodeURIComponent(staticRunId())}/${detail}`,
  );
  if (!response.ok) throw new Error(`published network evidence request failed (${response.status})`);
  return response.json();
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
    [formatCount(model.preDetonationEventCount || 0), "pre-detonation"],
    [formatCount(model.unknownPhaseEventCount || 0), "phase unknown"],
    [formatCount(model.processCount), "processes"],
    [formatCount(model.activityNodeCount), "activity nodes"],
    [formatCount(state.networkCaptureCount), "HTTP(S) captures"],
    [formatDuration(model.minTimestampNs, model.maxTimestampNs), "duration"],
  ];
  $("#pre-detonation-count").textContent = formatCount(model.preDetonationEventCount || 0);
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

function renderNetworkControls() {
  const section = $("#network-capture-section");
  const available = VIEWER.mode === "static" && state.networkCaptureCount > 0;
  section.hidden = !available;
  $("#network-capture-count").textContent = formatCount(state.networkCaptureCount);
}

function renderAssessment() {
  const section = $("#assessment-section");
  const assessment = state.assessment;
  section.hidden = !assessment;
  if (!assessment) return;
  const findings = assessment.findings || [];
  const verdict = $("#assessment-verdict");
  verdict.textContent = assessment.verdict || "unknown";
  verdict.className = `assessment-verdict ${assessment.verdict || "unknown"}`;
  $("#assessment-summary").textContent = `${formatRisk(assessment.riskScore)} · ${assessment.maxSeverity || "no severity"} · ${formatCount(findings.length)} rule finding${findings.length === 1 ? "" : "s"}`;
  const shortcuts = $("#finding-shortcuts");
  shortcuts.replaceChildren();
  for (const finding of findings) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "finding-shortcut";
    button.dataset.findingId = finding.findingId;
    const severity = document.createElement("b");
    severity.textContent = finding.severity;
    const summary = document.createElement("span");
    summary.textContent = `#${finding.evidenceSeqStart} · ${finding.summary}`;
    button.append(severity, summary);
    button.addEventListener("click", () => inspectFinding(finding));
    shortcuts.append(button);
  }
}

function formatRisk(value) {
  const score = Number(value);
  return Number.isFinite(score) ? `${score.toFixed(0)} risk` : "risk unavailable";
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

function calculateLayout(nodes = state.visible, { preservePositions = false } = {}) {
  stopSimulation();
  const previous = state.positions;
  state.layoutNodes = [...nodes];
  state.nodeById = new Map(state.model.nodes.map((node) => [node.id, node]));
  state.visibleEdges = state.model.edges.filter(
    (edge) => state.visibleIds.has(edge.source) && state.visibleIds.has(edge.target),
  );
  state.positions = new Map();

  state.layoutNodes.forEach((node, index) => {
    const retained = preservePositions ? previous.get(node.id) : null;
    const seeded = retained || initialPosition(node, index, state.layoutNodes.length);
    state.positions.set(node.id, {
      x: seeded.x,
      y: seeded.y,
      vx: retained?.vx || 0,
      vy: retained?.vy || 0,
      width: LAYOUT.nodeWidth,
      height: LAYOUT.nodeHeight,
      index,
      fixed: false,
    });
  });

  const warmup = state.layoutNodes.length < 300 ? 80
    : state.layoutNodes.length < 1_200 ? 38
      : state.layoutNodes.length < 3_000 ? 20 : 10;
  for (let index = 0; index < warmup; index += 1) {
    simulationStep(1 - (index / Math.max(1, warmup)) * .48);
  }
  startSimulation(.58);
}

function initialPosition(node, index, count) {
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  const jitter = hashFraction(node.id);
  const angle = index * goldenAngle + jitter * .9;
  const spacing = count > 2_000 ? 112 : count > 600 ? 126 : 144;
  const radius = Math.sqrt(index + 1) * spacing;
  const processBias = node.kind === "process" ? node.depth * 48 : 0;
  return {
    x: Math.cos(angle) * radius + processBias,
    y: Math.sin(angle) * radius,
  };
}

function hashFraction(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) / 0xffffffff;
}

function applyFilters({ resetLayout = false } = {}) {
  if (!state.model) return;
  const query = state.search.toLowerCase();
  state.visible = state.model.nodes.filter((node) => {
    if (node.preDetonation && !state.includePreDetonation) return false;
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
  calculateLayout(state.visible, { preservePositions: !resetLayout });
  $("#filter-layout-note").textContent = `${formatCount(state.visible.length)} visible nodes · force layout settling.`;
  $("#empty-state").hidden = state.visible.length !== 0;
  draw();
}

function refreshFilteredLayout() {
  calculateLayout(state.visible, { preservePositions: false });
  fitGraph();
  $("#filter-layout-note").textContent = `${formatCount(state.visible.length)} visible nodes · force layout reheated.`;
}

function startSimulation(alpha = .58) {
  state.simulationAlpha = Math.max(state.simulationAlpha, alpha);
  state.simulationTicks = 0;
  if (state.simulationFrame !== null || !state.layoutNodes.length) return;
  const frame = () => {
    state.simulationFrame = null;
    const steps = state.layoutNodes.length > 1_500 ? 1 : 2;
    for (let index = 0; index < steps; index += 1) {
      simulationStep(state.simulationAlpha);
      state.simulationAlpha *= .965;
      state.simulationTicks += 1;
    }
    draw();
    if (state.simulationAlpha > .012 && state.simulationTicks < 320) {
      state.simulationFrame = requestAnimationFrame(frame);
    } else {
      state.simulationAlpha = 0;
      $("#filter-layout-note").textContent = `${formatCount(state.visible.length)} visible nodes · layout settled.`;
    }
  };
  state.simulationFrame = requestAnimationFrame(frame);
}

function stopSimulation() {
  if (state.simulationFrame !== null) cancelAnimationFrame(state.simulationFrame);
  state.simulationFrame = null;
  state.simulationAlpha = 0;
}

function simulationStep(alpha) {
  const positions = state.layoutNodes.map((node) => state.positions.get(node.id)).filter(Boolean);
  if (!positions.length) return;

  for (const edge of state.visibleEdges) {
    const source = state.positions.get(edge.source);
    const target = state.positions.get(edge.target);
    if (!source || !target) continue;
    let dx = target.x - source.x;
    let dy = target.y - source.y;
    let distance = Math.hypot(dx, dy);
    if (distance < .001) {
      const angle = hashFraction(edge.id) * Math.PI * 2;
      dx = Math.cos(angle);
      dy = Math.sin(angle);
      distance = 1;
    }
    const desired = edge.kind === "activity" ? LAYOUT.activityLinkDistance : LAYOUT.processLinkDistance;
    const force = (distance - desired) * .012 * alpha;
    const fx = dx / distance * force;
    const fy = dy / distance * force;
    if (!source.fixed) {
      source.vx += fx;
      source.vy += fy;
    }
    if (!target.fixed) {
      target.vx -= fx;
      target.vy -= fy;
    }
  }

  const cellSize = LAYOUT.chargeRadius;
  const grid = new Map();
  for (const point of positions) {
    const cellX = Math.floor(point.x / cellSize);
    const cellY = Math.floor(point.y / cellSize);
    const key = `${cellX}:${cellY}`;
    if (!grid.has(key)) grid.set(key, []);
    grid.get(key).push(point);
  }

  for (const point of positions) {
    const cellX = Math.floor(point.x / cellSize);
    const cellY = Math.floor(point.y / cellSize);
    for (let offsetX = -1; offsetX <= 1; offsetX += 1) {
      for (let offsetY = -1; offsetY <= 1; offsetY += 1) {
        const neighbors = grid.get(`${cellX + offsetX}:${cellY + offsetY}`) || [];
        for (const other of neighbors) {
          if (other.index <= point.index) continue;
          let dx = other.x - point.x;
          let dy = other.y - point.y;
          let distance = Math.hypot(dx, dy);
          if (distance >= LAYOUT.chargeRadius) continue;
          if (distance < .001) {
            const angle = hashFraction(`${point.index}:${other.index}`) * Math.PI * 2;
            dx = Math.cos(angle);
            dy = Math.sin(angle);
            distance = 1;
          }
          const minimum = (Math.max(point.width, point.height) + Math.max(other.width, other.height)) / 2
            + LAYOUT.collisionPadding;
          let force = (1 - distance / LAYOUT.chargeRadius) * 1.1 * alpha;
          if (distance < minimum) force += (minimum - distance) * .055 * alpha;
          const fx = dx / distance * force;
          const fy = dy / distance * force;
          if (!point.fixed) {
            point.vx -= fx;
            point.vy -= fy;
          }
          if (!other.fixed) {
            other.vx += fx;
            other.vy += fy;
          }
        }
      }
    }
  }

  for (const point of positions) {
    if (point.fixed) {
      point.vx = 0;
      point.vy = 0;
      continue;
    }
    point.vx += -point.x * .0008 * alpha;
    point.vy += -point.y * .0008 * alpha;
    point.vx *= .76;
    point.vy *= .76;
    const speed = Math.hypot(point.vx, point.vy);
    const scale = speed > 24 ? 24 / speed : 1;
    point.x += point.vx * scale;
    point.y += point.vy * scale;
  }
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
  const view = visibleWorldBounds(rect);

  context.save();
  context.translate(state.panX, state.panY);
  context.scale(state.zoom, state.zoom);
  for (const edge of state.visibleEdges.filter((candidate) => !state.threatEdgeIds.has(candidate.id))) {
    const source = state.positions.get(edge.source);
    const target = state.positions.get(edge.target);
    if (!source || !target || !edgeIntersectsView(source, target, view)) continue;
    drawEdge(edge);
  }
  for (const edge of state.visibleEdges.filter((candidate) => state.threatEdgeIds.has(candidate.id))) {
    const source = state.positions.get(edge.source);
    const target = state.positions.get(edge.target);
    if (!source || !target || !edgeIntersectsView(source, target, view)) continue;
    drawEdge(edge);
  }
  for (const node of state.visible.filter((candidate) => !state.threatNodeIds.has(candidate.id))) {
    const position = state.positions.get(node.id);
    if (position && nodeIntersectsView(position, view)) drawNode(node);
  }
  for (const node of state.visible.filter((candidate) => state.threatNodeIds.has(candidate.id))) {
    const position = state.positions.get(node.id);
    if (position && nodeIntersectsView(position, view)) drawNode(node);
  }
  context.restore();
}

function visibleWorldBounds(rect) {
  const padding = Math.max(LAYOUT.nodeWidth, LAYOUT.nodeHeight);
  return {
    left: -state.panX / state.zoom - padding,
    right: (rect.width - state.panX) / state.zoom + padding,
    top: -state.panY / state.zoom - padding,
    bottom: (rect.height - state.panY) / state.zoom + padding,
  };
}

function nodeIntersectsView(position, view) {
  return position.x + position.width / 2 >= view.left
    && position.x - position.width / 2 <= view.right
    && position.y + position.height / 2 >= view.top
    && position.y - position.height / 2 <= view.bottom;
}

function edgeIntersectsView(source, target, view) {
  return Math.max(source.x, target.x) >= view.left
    && Math.min(source.x, target.x) <= view.right
    && Math.max(source.y, target.y) >= view.top
    && Math.min(source.y, target.y) <= view.bottom;
}

function formatNodeTime(node) {
  if (node.timeOffsetNs === null || node.timeOffsetNs === undefined) return "no time";
  return formatOffset(Number(node.timeOffsetNs));
}

function drawEdge(edge) {
  const source = state.positions.get(edge.source);
  const target = state.positions.get(edge.target);
  if (!source || !target) return;
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const distance = Math.hypot(dx, dy);
  if (distance < .001) return;
  const nx = dx / distance;
  const ny = dy / distance;
  const sourceInset = rayDistanceToNode(source, nx, ny);
  const targetInset = rayDistanceToNode(target, -nx, -ny);
  const startX = source.x + nx * sourceInset;
  const startY = source.y + ny * sourceInset;
  const endX = target.x - nx * targetInset;
  const endY = target.y - ny * targetInset;
  context.save();
  const isProcess = edge.kind !== "activity";
  const isThreat = state.threatEdgeIds.has(edge.id);
  context.strokeStyle = isThreat
    ? "rgba(255, 95, 86, .96)"
    : (isProcess ? "rgba(185, 245, 106, .52)" : "rgba(109, 214, 232, .30)");
  context.fillStyle = context.strokeStyle;
  context.lineWidth = (isThreat ? 3.1 : (isProcess ? 1.45 : 1.05)) / state.zoom;
  if (edge.kind === "exec") context.setLineDash([5 / state.zoom, 4 / state.zoom]);
  context.beginPath();
  context.moveTo(startX, startY);
  context.lineTo(endX, endY);
  context.stroke();
  context.setLineDash([]);
  const arrow = 5.5 / state.zoom;
  context.beginPath();
  context.moveTo(endX, endY);
  context.lineTo(endX - nx * arrow * 1.8 + ny * arrow, endY - ny * arrow * 1.8 - nx * arrow);
  context.lineTo(endX - nx * arrow * 1.8 - ny * arrow, endY - ny * arrow * 1.8 + nx * arrow);
  context.closePath();
  context.fill();

  const selectedEdge = state.selected && (edge.source === state.selected || edge.target === state.selected);
  if ((isProcess && state.zoom >= .35) || (selectedEdge && state.zoom >= .28)) {
    drawEdgeLabel(edge.label, (startX + endX) / 2, (startY + endY) / 2);
  }
  context.restore();
}

function rayDistanceToNode(position, nx, ny) {
  const horizontal = Math.abs(nx) < .0001 ? Infinity : position.width / 2 / Math.abs(nx);
  const vertical = Math.abs(ny) < .0001 ? Infinity : position.height / 2 / Math.abs(ny);
  return Math.min(horizontal, vertical);
}

function drawEdgeLabel(label, x, y) {
  if (!label) return;
  const fontSize = 9 / state.zoom;
  const paddingX = 4 / state.zoom;
  const paddingY = 2.5 / state.zoom;
  context.font = `${fontSize}px ui-monospace, SFMono-Regular, Menlo, monospace`;
  const width = context.measureText(label).width + paddingX * 2;
  const height = fontSize + paddingY * 2;
  context.fillStyle = "rgba(7, 16, 15, .88)";
  context.fillRect(x - width / 2, y - height / 2, width, height);
  context.fillStyle = "#8fa9a1";
  context.textAlign = "center";
  context.textBaseline = "middle";
  context.fillText(label, x, y);
  context.textAlign = "start";
  context.textBaseline = "alphabetic";
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
  context.globalAlpha = node.preDetonation ? .48 : (node.phaseKnown === false ? .7 : 1);
  const isThreat = state.threatNodeIds.has(node.id);
  context.fillStyle = isThreat
    ? "rgba(88, 23, 22, .98)"
    : (selected ? "rgba(101, 229, 194, .17)" : "rgba(17, 36, 32, .97)");
  context.fill();
  context.lineWidth = (isThreat ? 3.1 : (selected ? 2.3 : 1.2)) / state.zoom;
  const color = COLORS[node.category] || COLORS.other;
  context.strokeStyle = isThreat ? "#ff5f56" : (selected ? "#ffffff" : color);
  context.stroke();
  context.fillStyle = isThreat ? "#ff5f56" : color;
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
  const phase = node.phaseKnown === false
    ? "phase unknown · "
    : (node.preDetonation ? "pre-detonation · " : "");
  if (node.kind === "process") return `${phase}pid ${node.pid} · ${node.processKind}`;
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
  return phase + parts.join(" · ");
}

function phaseLabel(item) {
  if (item.phaseKnown === false) return "unknown (legacy capture)";
  return item.preDetonation ? "pre-detonation" : "detonation";
}

function roundedRect(x, y, width, height, radius) {
  context.beginPath();
  context.roundRect(x, y, width, height, radius);
}

function fitGraph() {
  const rect = canvas.getBoundingClientRect();
  const positions = [...state.positions.values()];
  if (!positions.length) {
    state.zoom = 1;
    state.panX = rect.width / 2;
    state.panY = rect.height / 2;
    draw();
    return;
  }
  let left = Infinity;
  let right = -Infinity;
  let top = Infinity;
  let bottom = -Infinity;
  for (const point of positions) {
    left = Math.min(left, point.x - point.width / 2);
    right = Math.max(right, point.x + point.width / 2);
    top = Math.min(top, point.y - point.height / 2);
    bottom = Math.max(bottom, point.y + point.height / 2);
  }
  const width = Math.max(1, right - left);
  const height = Math.max(1, bottom - top);
  const availableWidth = Math.max(1, rect.width - LAYOUT.fitPadding * 2);
  const availableHeight = Math.max(1, rect.height - LAYOUT.fitPadding * 2);
  state.zoom = Math.max(.05, Math.min(1.35, availableWidth / width, availableHeight / height));
  state.panX = rect.width / 2 - (left + right) / 2 * state.zoom;
  state.panY = rect.height / 2 - (top + bottom) / 2 * state.zoom;
  draw();
}

function zoomBy(factor, centerX = canvas.clientWidth / 2, centerY = canvas.clientHeight / 2) {
  const previous = state.zoom;
  const next = Math.max(.05, Math.min(5, state.zoom * factor));
  if (next === previous) return;
  const worldX = (centerX - state.panX) / previous;
  const worldY = (centerY - state.panY) / previous;
  state.zoom = next;
  state.panX = centerX - worldX * next;
  state.panY = centerY - worldY * next;
  draw();
}

function hitTest(screenX, screenY) {
  const x = (screenX - state.panX) / state.zoom;
  const y = (screenY - state.panY) / state.zoom;
  for (let index = state.visible.length - 1; index >= 0; index -= 1) {
    const node = state.visible[index];
    const point = state.positions.get(node.id);
    if (point && Math.abs(x - point.x) <= point.width / 2 && Math.abs(y - point.y) <= point.height / 2) return node;
  }
  return null;
}

function inspectAssessment() {
  const assessment = state.assessment;
  if (!assessment) return;
  clearFindingHighlight();
  shell.classList.add("details-open");
  $("#details-title").textContent = `${titleCase(assessment.verdict)} verdict`;
  const body = $("#details-body");
  body.replaceChildren();
  const findings = assessment.findings || [];
  body.append(detailGrid([
    ["Verdict", titleCase(assessment.verdict)],
    ["Risk score", formatRisk(assessment.riskScore)],
    ["Maximum severity", titleCase(assessment.maxSeverity)],
    ["Coverage", assessment.coverageState],
    ["Assessed", formatIso(assessment.assessedAt)],
    ["Rule findings", formatCount(findings.length)],
  ]));
  const explanation = document.createElement("p");
  explanation.className = "verdict-explanation";
  explanation.textContent = findings.length
    ? "This verdict was produced by the deterministic rules below. Select a finding to highlight its recorded evidence and process chain in red."
    : "No rule findings were recorded for this assessment.";
  body.append(explanation);
  const list = document.createElement("div");
  list.className = "finding-list";
  for (const finding of findings) list.append(findingButton(finding));
  body.append(list);
  draw();
}

function findingButton(finding) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "finding-card";
  const heading = document.createElement("span");
  const severity = document.createElement("b");
  severity.className = `finding-severity ${finding.severity}`;
  severity.textContent = finding.severity;
  const rule = document.createElement("code");
  rule.textContent = finding.ruleId;
  heading.append(severity, rule);
  const summary = document.createElement("strong");
  summary.textContent = finding.summary;
  const evidence = document.createElement("small");
  evidence.textContent = `#${finding.evidenceSeqStart}${finding.evidenceSeqEnd === finding.evidenceSeqStart ? "" : `–#${finding.evidenceSeqEnd}`} · ${finding.sinkKind}: ${finding.sinkValue}`;
  button.append(heading, summary, evidence);
  button.addEventListener("click", () => inspectFinding(finding));
  return button;
}

function inspectFinding(finding) {
  state.activeFinding = finding.findingId;
  const chain = findingChain(finding);
  state.threatNodeIds = chain.nodes;
  state.threatEdgeIds = chain.edges;
  state.selected = null;
  shell.classList.add("details-open");
  $("#details-title").textContent = finding.summary;
  const body = $("#details-body");
  body.replaceChildren();
  body.append(detailGrid([
    ["Rule", finding.ruleId],
    ["Severity", titleCase(finding.severity)],
    ["Category", titleCase(finding.category)],
    ["Source", finding.sourceMarker || "not retained"],
    ["Sink", `${finding.sinkKind}: ${finding.sinkValue}`],
    ["Evidence", `#${finding.evidenceSeqStart}${finding.evidenceSeqEnd === finding.evidenceSeqStart ? "" : `–#${finding.evidenceSeqEnd}`}`],
    ["Highlighted", `${formatCount(chain.nodes.size)} nodes · ${formatCount(chain.edges.size)} edges`],
  ]));
  const explanation = document.createElement("p");
  explanation.className = "verdict-explanation danger";
  explanation.textContent = finding.summary;
  body.append(explanation);
  const note = document.createElement("p");
  note.className = "muted";
  note.textContent = "Red nodes contain the rule evidence or connect it through process ancestry. Red edges are the shortest available graph path between recorded source and sink evidence; the dashboard does not invent missing telemetry.";
  body.append(note);
  body.append(sectionTitle("Recorded evidence events"));
  const events = document.createElement("div");
  events.className = "event-list";
  for (const seq of evidenceSequences(finding)) {
    events.append(eventIdButton(seq, `Evidence #${seq}`, finding.ruleId));
  }
  body.append(events);
  const back = document.createElement("button");
  back.type = "button";
  back.className = "load-more";
  back.textContent = "Back to all verdict findings";
  back.addEventListener("click", inspectAssessment);
  body.append(back);
  markActiveFindingShortcut();
  draw();
}

function evidenceSequences(finding) {
  const start = Number(finding.evidenceSeqStart);
  const end = Number(finding.evidenceSeqEnd);
  return start === end ? [start] : [start, end];
}

function findingChain(finding) {
  const nodes = new Set();
  const edges = new Set();
  const sequences = new Set(evidenceSequences(finding).map(String));
  const evidenceNodes = state.model.nodes.filter((node) =>
    (node.eventIds || []).some((seq) => sequences.has(String(seq))),
  );
  for (const node of evidenceNodes) nodes.add(node.id);

  const marker = String(finding.sourceMarker || "").trim().toLowerCase();
  const genericMarkers = new Set(["", "skill", "untrusted-network", "sensitive-source"]);
  let sourceNode = null;
  if (!genericMarkers.has(marker)) {
    const candidates = state.model.nodes.filter((node) => {
      if (node.kind === "process") return false;
      const text = [node.target, node.command, node.sublabel, node.label]
        .filter(Boolean).join(" ").toLowerCase();
      return text.includes(marker);
    });
    candidates.sort((left, right) => latestEventSequence(right) - latestEventSequence(left));
    sourceNode = candidates.find((node) => latestEventSequence(node) <= Number(finding.evidenceSeqEnd)) || null;
    if (sourceNode) nodes.add(sourceNode.id);
  }

  const adjacency = new Map();
  const incoming = new Map();
  for (const edge of state.model.edges) {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
    if (!adjacency.has(edge.target)) adjacency.set(edge.target, []);
    adjacency.get(edge.source).push({ node: edge.target, edge });
    adjacency.get(edge.target).push({ node: edge.source, edge });
    if (!incoming.has(edge.target)) incoming.set(edge.target, []);
    incoming.get(edge.target).push(edge);
  }

  for (const node of evidenceNodes) addAncestorChain(node.id, incoming, nodes, edges);
  if (sourceNode) addAncestorChain(sourceNode.id, incoming, nodes, edges);
  if (sourceNode) {
    for (const target of evidenceNodes) addShortestPath(sourceNode.id, target.id, adjacency, nodes, edges);
  }
  return { nodes, edges };
}

function latestEventSequence(node) {
  return Math.max(0, ...(node.eventIds || []).map(Number));
}

function addAncestorChain(start, incoming, nodes, edges) {
  const queue = [start];
  const visited = new Set(queue);
  while (queue.length) {
    const current = queue.shift();
    for (const edge of incoming.get(current) || []) {
      if (edge.kind === "activity" || state.nodeById.get(edge.source)?.kind === "process") {
        nodes.add(edge.source);
        edges.add(edge.id);
        if (!visited.has(edge.source)) {
          visited.add(edge.source);
          queue.push(edge.source);
        }
      }
    }
  }
}

function addShortestPath(start, target, adjacency, nodes, edges) {
  if (start === target) return;
  const queue = [start];
  const previous = new Map([[start, null]]);
  while (queue.length && !previous.has(target)) {
    const current = queue.shift();
    for (const step of adjacency.get(current) || []) {
      if (previous.has(step.node)) continue;
      previous.set(step.node, { node: current, edge: step.edge });
      queue.push(step.node);
    }
  }
  if (!previous.has(target)) return;
  let current = target;
  nodes.add(current);
  while (current !== start) {
    const step = previous.get(current);
    if (!step) break;
    nodes.add(step.node);
    edges.add(step.edge.id);
    current = step.node;
  }
}

function clearFindingHighlight() {
  state.activeFinding = null;
  state.threatNodeIds = new Set();
  state.threatEdgeIds = new Set();
  markActiveFindingShortcut();
}

function markActiveFindingShortcut() {
  for (const button of document.querySelectorAll(".finding-shortcut")) {
    button.classList.toggle("active", button.dataset.findingId === state.activeFinding);
  }
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
    ["Phase", phaseLabel(node)],
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
    ["Phase", phaseLabel(event)],
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

async function browseNetworkCaptures() {
  shell.classList.add("details-open");
  state.selected = null;
  $("#details-title").textContent = "Intercepted downloads";
  const body = $("#details-body");
  body.replaceChildren();
  const loading = document.createElement("p");
  loading.className = "muted";
  loading.textContent = "Loading bounded HTTP(S) response evidence…";
  body.append(loading);
  try {
    const index = await staticNetworkIndex();
    const publishedCount = Number(index.publishedCaptureCount ?? (index.captures || []).length);
    const publicationNote = index.publicationTruncated
      ? ` Showing the first ${formatCount(publishedCount)} here; the complete transcript remains in the repository run evidence.`
      : "";
    loading.textContent = `${formatCount(index.captureCount)} request/response capture(s).${publicationNote} Response bodies are inert evidence until you explicitly download them.`;
    const list = document.createElement("div");
    list.className = "event-list";
    for (const capture of index.captures || []) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "event-button";
      const code = document.createElement("code");
      code.textContent = capture.status ? String(capture.status) : "ERR";
      const name = document.createElement("span");
      name.textContent = `${capture.method || "GET"} ${capture.url || "unknown URL"}`;
      const detail = document.createElement("small");
      detail.textContent = capture.failure
        ? capture.failure
        : formatBytes(capture.responseBytes || 0);
      button.append(code, name, detail);
      button.addEventListener("click", () => inspectNetworkCapture(capture));
      list.append(button);
    }
    body.append(list);
  } catch (error) {
    loading.textContent = `Could not load network evidence: ${error.message}`;
  }
  draw();
}

async function inspectNetworkCapture(summary) {
  shell.classList.add("details-open");
  state.selected = null;
  $("#details-title").textContent = `${summary.method || "GET"} response`;
  const body = $("#details-body");
  body.replaceChildren();
  const loading = document.createElement("p");
  loading.className = "muted";
  loading.textContent = "Loading exact captured response bytes…";
  body.append(loading);
  try {
    const capture = await staticNetworkDetail(summary);
    const response = capture.response || {};
    const request = capture.request || {};
    loading.remove();
    body.append(detailGrid([
      ["URL", capture.url],
      ["Resolved IP", capture.resolved_ip],
      ["Transport", capture.tls_intercepted ? "TLS intercepted" : "cleartext HTTP"],
      ["Status", response.status === null || response.status === undefined ? "unavailable" : String(response.status)],
      ["Response bytes", formatBytes(response.original_bytes || 0)],
      ["Body SHA-256", response.body_sha256],
      ["Failure", capture.failure || "none"],
      ["Capture truncated", response.capture_truncated ? "yes" : "no"],
    ]));

    body.append(sectionTitle("Request headers"));
    body.append(networkHeaders(request.headers));
    body.append(sectionTitle("Response headers"));
    body.append(networkHeaders(response.headers));

    const encoded = String(response.body_base64 || "");
    body.append(sectionTitle("Response body preview"));
    const preview = document.createElement("pre");
    preview.className = "content-preview";
    preview.textContent = encoded
      ? base64Preview(encoded)
      : "(empty response body)";
    body.append(preview);
    if (encoded) {
      const download = document.createElement("button");
      download.type = "button";
      download.className = "load-more";
      download.textContent = `Download captured response (${formatBytes(response.original_bytes || 0)})`;
      download.addEventListener("click", () => downloadCapturedBody(capture));
      body.append(download);
    }
    const raw = document.createElement("details");
    raw.className = "raw-details";
    const rawSummary = document.createElement("summary");
    rawSummary.textContent = "Raw capture metadata";
    const rawValue = document.createElement("pre");
    rawValue.className = "raw-event";
    const metadata = structuredClone(capture);
    if (metadata.response) metadata.response.body_base64 = `[${encoded.length} base64 characters]`;
    rawValue.textContent = JSON.stringify(metadata, null, 2);
    raw.append(rawSummary, rawValue);
    body.append(raw);
  } catch (error) {
    loading.textContent = `Could not load response evidence: ${error.message}`;
  }
  draw();
}

function networkHeaders(headers) {
  const preview = document.createElement("pre");
  preview.className = "content-preview";
  preview.textContent = Array.isArray(headers) && headers.length
    ? headers.map(([name, value]) => `${name}: ${value}`).join("\n")
    : "(none retained)";
  return preview;
}

function base64Preview(encoded) {
  const bounded = encoded.slice(0, 8192);
  const aligned = bounded.slice(0, bounded.length - (bounded.length % 4));
  try {
    const decoded = atob(aligned);
    const bytes = Uint8Array.from(decoded, (value) => value.charCodeAt(0));
    const printable = [...bytes].filter(
      (value) => value === 9 || value === 10 || value === 13 || (value >= 32 && value <= 126),
    ).length;
    const suffix = encoded.length > bounded.length ? "\n\n[…preview truncated…]" : "";
    if (!bytes.length || printable / bytes.length >= .72) {
      return new TextDecoder().decode(bytes) + suffix;
    }
    return [...bytes]
      .slice(0, 1024)
      .map((value, index) => `${index && index % 16 === 0 ? "\n" : ""}${value.toString(16).padStart(2, "0")}`)
      .join(" ") + suffix;
  } catch {
    return "(response body encoding could not be previewed)";
  }
}

function downloadCapturedBody(capture) {
  const encoded = String(capture.response?.body_base64 || "");
  const decoded = atob(encoded);
  const bytes = new Uint8Array(decoded.length);
  for (let index = 0; index < decoded.length; index += 1) {
    bytes[index] = decoded.charCodeAt(index);
  }
  const contentType = (capture.response?.headers || [])
    .find(([name]) => String(name).toLowerCase() === "content-type")?.[1]
    || "application/octet-stream";
  let filename = "captured-response.bin";
  try {
    const basename = new URL(capture.url).pathname.split("/").filter(Boolean).pop();
    if (basename) filename = basename.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 128);
  } catch {}
  const href = URL.createObjectURL(new Blob([bytes], { type: contentType }));
  const link = document.createElement("a");
  link.href = href;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(href), 0);
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
function titleCase(value) { return String(value || "unknown").replaceAll("-", " ").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }

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
  const rect = canvas.getBoundingClientRect();
  const node = hitTest(event.clientX - rect.left, event.clientY - rect.top);
  state.dragging = true;
  state.dragNode = node?.id || null;
  state.dragStart = {
    x: event.clientX,
    y: event.clientY,
    panX: state.panX,
    panY: state.panY,
  };
  state.pointerStart = { x: event.clientX, y: event.clientY };
  if (state.dragNode) {
    const point = state.positions.get(state.dragNode);
    if (point) point.fixed = true;
  }
  canvas.classList.add("dragging");
});

canvas.addEventListener("pointermove", (event) => {
  if (!state.dragging) return;
  if (state.dragNode) {
    const rect = canvas.getBoundingClientRect();
    const point = state.positions.get(state.dragNode);
    if (point) {
      point.x = (event.clientX - rect.left - state.panX) / state.zoom;
      point.y = (event.clientY - rect.top - state.panY) / state.zoom;
      point.vx = 0;
      point.vy = 0;
      point.fixed = true;
      startSimulation(.2);
    }
  } else {
    state.panX = state.dragStart.panX + event.clientX - state.dragStart.x;
    state.panY = state.dragStart.panY + event.clientY - state.dragStart.y;
  }
  draw();
});

canvas.addEventListener("pointerup", (event) => {
  if (!state.dragging) return;
  state.dragging = false;
  canvas.classList.remove("dragging");
  const distance = Math.hypot(event.clientX - state.pointerStart.x, event.clientY - state.pointerStart.y);
  if (state.dragNode) {
    const point = state.positions.get(state.dragNode);
    if (point) point.fixed = false;
    if (distance >= 5) startSimulation(.24);
  }
  state.dragNode = null;
  if (distance < 5) {
    const rect = canvas.getBoundingClientRect();
    const node = hitTest(event.clientX - rect.left, event.clientY - rect.top);
    if (node) inspectNode(node);
  }
});

canvas.addEventListener("pointercancel", () => {
  if (state.dragNode) {
    const point = state.positions.get(state.dragNode);
    if (point) point.fixed = false;
  }
  state.dragging = false;
  state.dragNode = null;
  canvas.classList.remove("dragging");
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

$("#refresh-layout").addEventListener("click", refreshFilteredLayout);
$("#all-events").addEventListener("click", () => browseEvents(0));
$("#assessment-details").addEventListener("click", inspectAssessment);
$("#network-captures").addEventListener("click", browseNetworkCaptures);
$("#close-details").addEventListener("click", () => {
  shell.classList.remove("details-open");
  state.selected = null;
  draw();
});
$("#bucket").addEventListener("change", () => loadGraph({ preserveView: true }));
$("#group").addEventListener("change", () => loadGraph({ preserveView: true }));
$("#transport").addEventListener("change", (event) => { state.transport = event.target.value; applyFilters(); });
$("#direction").addEventListener("change", (event) => { state.direction = event.target.value; applyFilters(); });
$("#show-pre-detonation").addEventListener("change", (event) => {
  state.includePreDetonation = event.target.checked;
  applyFilters();
});
$("#search").addEventListener("input", (event) => { state.search = event.target.value.trim(); applyFilters(); });

new ResizeObserver(() => {
  if (!state.model) return;
  draw();
}).observe(canvasWrap);

if (VIEWER.mode === "static") {
  $("#density-controls").hidden = true;
  const indexLink = $("#index-link");
  indexLink.href = VIEWER.indexUrl || "../";
  indexLink.hidden = false;
}

loadGraph();
