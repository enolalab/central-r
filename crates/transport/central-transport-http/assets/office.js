// office.js -- renders the LIVE task projection served by /app/office as a
// top-down "office": each task is a worker standing in its status room. It is
// an external same-origin script (never inline) because
// rendering.MandatoryContentSecurityPolicy sets script-src 'self' with no
// 'unsafe-inline'. It reads the per-task data-* attributes the "office"
// template emits (id/title/label/reason) -- there is no executable data
// island -- and never fetches an external host, so the strict self-only CSP
// holds. Hovering a worker shows a tooltip; clicking one opens its detail
// page.
(function () {
  "use strict";

  var canvas = document.getElementById("office");
  var list = document.getElementById("office-agents");
  if (!canvas || !list) {
    return;
  }
  var ctx = canvas.getContext("2d");
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // The six live canonical labels, each a room, in a fixed 3x2 order.
  var ROOMS = [
    { label: "Queued", color: "#8a94a6" },
    { label: "Running", color: "#4c8dff" },
    { label: "Waiting", color: "#ffb340" },
    { label: "Settling", color: "#a78bff" },
    { label: "Unsuccessful", color: "#ff6b6b" },
    { label: "Completed", color: "#3ddc97" }
  ];
  var COLOR = {};
  ROOMS.forEach(function (r) { COLOR[r.label] = r.color; });

  // readAgents parses the server-rendered task rows from an #office-agents
  // element. It preserves each worker's animation phase across a live refresh
  // (keyed by task id) so re-fetching does not make the whole office twitch.
  function readAgents(listEl, previous) {
    var priorPhase = {};
    (previous || []).forEach(function (a) { priorPhase[a.id] = a.ph; });
    var out = [];
    Array.prototype.forEach.call(listEl.querySelectorAll("li"), function (li) {
      var id = li.getAttribute("data-id") || "";
      out.push({
        id: id,
        title: li.getAttribute("data-title") || "",
        label: li.getAttribute("data-label") || "Queued",
        reason: li.getAttribute("data-reason") || "",
        x: 0, y: 0,
        ph: id in priorPhase ? priorPhase[id] : Math.random() * 6.28
      });
    });
    return out;
  }

  var agents = readAgents(list, null);

  // The activity ticker: recent events are embedded as #office-events rows
  // (task id + monotonic sequence). We track the highest sequence seen; on a
  // live refresh any task with a newer event gets flashed. Seeding maxSeq from
  // the initial page means the first load never flashes the whole office.
  var eventsList = document.getElementById("office-events");
  function readEvents(el) {
    var out = [];
    if (!el) { return out; }
    Array.prototype.forEach.call(el.querySelectorAll("li"), function (li) {
      out.push({ task: li.getAttribute("data-task") || "", seq: parseInt(li.getAttribute("data-seq") || "0", 10) || 0 });
    });
    return out;
  }
  function maxSeqOf(evs) { var m = 0; evs.forEach(function (e) { if (e.seq > m) { m = e.seq; } }); return m; }
  var maxSeq = maxSeqOf(readEvents(eventsList));
  var nowMs = 0;

  var W = 0, H = 0, dpr = 1, hovered = null;
  var rooms = [];

  function layout() {
    var cssW = canvas.clientWidth || canvas.parentElement.clientWidth || 800;
    W = cssW;
    H = Math.max(360, Math.round(cssW * 0.58));
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    canvas.style.height = H + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    var P = 14, G = 10, cols = 3, rowsN = 2;
    var roomW = (W - 2 * P - (cols - 1) * G) / cols;
    var roomH = (H - 2 * P - (rowsN - 1) * G) / rowsN;
    rooms = ROOMS.map(function (r, i) {
      var c = i % cols, row = Math.floor(i / cols);
      return {
        label: r.label, color: r.color,
        x: P + c * (roomW + G), y: P + row * (roomH + G), w: roomW, h: roomH,
        agents: []
      };
    });
    var byLabel = {};
    rooms.forEach(function (rm) { byLabel[rm.label] = rm; });
    agents.forEach(function (a) { (byLabel[a.label] || rooms[0]).agents.push(a); });

    // Place each room's agents in a slot grid below the room title.
    rooms.forEach(function (rm) {
      var slot = 46, padX = 14, titleH = 30;
      var innerW = rm.w - padX * 2;
      var perRow = Math.max(1, Math.floor(innerW / slot));
      rm.agents.forEach(function (a, i) {
        var col = i % perRow, r = Math.floor(i / perRow);
        a.x = rm.x + padX + col * slot + slot / 2;
        a.y = rm.y + titleH + 16 + r * (slot + 6);
      });
    });
  }

  function roundRect(x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  function worker(a, t) {
    var col = COLOR[a.label] || "#8a94a6";
    // activity flash: an expanding, fading ring when this task recently emitted
    // an event (set on live refresh; see below).
    if (a.flashUntil && nowMs < a.flashUntil) {
      var fp = 1 - (a.flashUntil - nowMs) / 1600;
      ctx.save();
      ctx.globalAlpha = 0.6 * (1 - fp);
      ctx.strokeStyle = col;
      ctx.lineWidth = 2.5;
      ctx.beginPath();
      ctx.arc(a.x, a.y - 8, 14 + fp * 18, 0, 6.3);
      ctx.stroke();
      ctx.restore();
    }
    var bob = 0;
    if (!reduce) {
      bob = a.label === "Running" ? Math.abs(Math.sin(t * 5 + a.ph)) * 1.6
          : a.label === "Unsuccessful" ? 0 : Math.sin(t * 1.8 + a.ph) * 1.4;
    }
    var cx = a.x, cy = a.y - bob;
    // desk hint
    ctx.fillStyle = "rgba(255,255,255,0.05)";
    roundRect(cx - 15, a.y + 12, 30, 7, 3); ctx.fill();
    // shadow
    ctx.fillStyle = "rgba(0,0,0,0.28)";
    ctx.beginPath(); ctx.ellipse(cx, a.y + 14, 11, 4, 0, 0, 6.3); ctx.fill();
    // focus ring
    if (a === hovered) {
      ctx.strokeStyle = "#ffffffb0"; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.ellipse(cx, a.y + 14, 14, 6, 0, 0, 6.3); ctx.stroke();
    }
    // body
    ctx.fillStyle = col;
    roundRect(cx - 8, cy - 8, 16, 20, 6); ctx.fill();
    ctx.fillStyle = "rgba(255,255,255,0.18)"; roundRect(cx - 8, cy - 8, 3, 20, 2); ctx.fill();
    // head
    ctx.fillStyle = "#f2d2ab";
    ctx.beginPath(); ctx.arc(cx, cy - 14, 6.5, 0, 6.3); ctx.fill();
    // marker for the attention states
    if (a.label === "Waiting" || a.label === "Unsuccessful") {
      ctx.fillStyle = "#0b0e18";
      roundRect(cx + 4, cy - 26, 13, 13, 3); ctx.fill();
      ctx.strokeStyle = col; ctx.lineWidth = 1.2; ctx.stroke();
      ctx.fillStyle = col; ctx.font = "700 11px ui-monospace, monospace";
      ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.fillText(a.label === "Waiting" ? "?" : "!", cx + 10.5, cy - 19);
    }
  }

  function drawTooltip(a, mx, my) {
    var lines = [a.title || "(untitled)", a.label + (a.reason ? " — " + a.reason : "")];
    ctx.font = "12px system-ui, sans-serif";
    var wdt = 0;
    lines.forEach(function (l) { wdt = Math.max(wdt, ctx.measureText(l).width); });
    var bw = wdt + 18, bh = lines.length * 17 + 12;
    var x = Math.min(mx + 12, W - bw - 6), y = Math.min(my + 12, H - bh - 6);
    ctx.fillStyle = "#0b0e18f2"; roundRect(x, y, bw, bh, 8); ctx.fill();
    ctx.strokeStyle = "#33406a"; ctx.lineWidth = 1; ctx.stroke();
    ctx.textAlign = "left"; ctx.textBaseline = "top";
    ctx.fillStyle = "#eef2fb"; ctx.font = "600 12px system-ui, sans-serif";
    ctx.fillText(lines[0], x + 9, y + 7);
    ctx.fillStyle = "#aebbd4"; ctx.font = "12px system-ui, sans-serif";
    ctx.fillText(lines[1], x + 9, y + 24);
  }

  var mouse = { x: -1, y: -1, on: false };

  function draw(ms) {
    nowMs = ms || 0;
    var t = (ms || 0) / 1000;
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = "#0e1220"; ctx.fillRect(0, 0, W, H);
    rooms.forEach(function (rm) {
      ctx.fillStyle = "#161b2e"; roundRect(rm.x, rm.y, rm.w, rm.h, 10); ctx.fill();
      ctx.fillStyle = rm.color; ctx.globalAlpha = 0.10; roundRect(rm.x, rm.y, rm.w, rm.h, 10); ctx.fill(); ctx.globalAlpha = 1;
      ctx.strokeStyle = "#252c45"; ctx.lineWidth = 1; roundRect(rm.x, rm.y, rm.w, rm.h, 10); ctx.stroke();
      // title bar
      ctx.fillStyle = rm.color; ctx.beginPath(); ctx.arc(rm.x + 14, rm.y + 16, 4, 0, 6.3); ctx.fill();
      ctx.fillStyle = "#dbe4f5"; ctx.font = "600 13px system-ui, sans-serif";
      ctx.textAlign = "left"; ctx.textBaseline = "middle";
      ctx.fillText(rm.label, rm.x + 24, rm.y + 16);
      ctx.fillStyle = "#8a94a6"; ctx.font = "12px ui-monospace, monospace"; ctx.textAlign = "right";
      ctx.fillText(String(rm.agents.length), rm.x + rm.w - 12, rm.y + 16);
    });
    rooms.forEach(function (rm) { rm.agents.forEach(function (a) { worker(a, t); }); });
    if (hovered && mouse.on) { drawTooltip(hovered, mouse.x, mouse.y); }
    if (!reduce) { window.requestAnimationFrame(draw); }
  }

  function pick(mx, my) {
    var best = null, bd = 22;
    agents.forEach(function (a) {
      var d = Math.hypot(mx - a.x, my - (a.y - 8));
      if (d < bd) { bd = d; best = a; }
    });
    return best;
  }

  canvas.addEventListener("mousemove", function (e) {
    var b = canvas.getBoundingClientRect();
    mouse.x = e.clientX - b.left; mouse.y = e.clientY - b.top; mouse.on = true;
    hovered = pick(mouse.x, mouse.y);
    canvas.style.cursor = hovered ? "pointer" : "default";
    if (reduce) { draw(0); }
  });
  canvas.addEventListener("mouseleave", function () {
    mouse.on = false; hovered = null; canvas.style.cursor = "default";
    if (reduce) { draw(0); }
  });
  canvas.addEventListener("click", function () {
    if (hovered && hovered.id) {
      window.location.href = "/app/tasks/detail?id=" + encodeURIComponent(hovered.id);
    }
  });

  // Live refresh: re-fetch this same-origin page, extract the fresh task rows,
  // and rebuild the office in place so it tracks real task-state changes
  // without a reload. It mirrors tasks_poll.js -- same-origin fetch, DOMParser,
  // stop on a non-2xx (session expired / route gone) -- and pauses while the
  // tab is hidden to stay polite. It is data-only: the animation loop (or a
  // one-shot draw under reduced motion) renders whatever `agents` currently
  // holds.
  var POLL_MS = 5000;

  function schedule() { window.setTimeout(refresh, POLL_MS); }

  function refresh() {
    if (document.hidden) { schedule(); return; }
    fetch(window.location.href, { credentials: "same-origin" })
      .then(function (resp) {
        if (!resp.ok) { throw new Error("office refresh not ok: " + resp.status); }
        return resp.text();
      })
      .then(function (html) {
        var doc = new DOMParser().parseFromString(html, "text/html");
        var freshList = doc.getElementById("office-agents");
        if (freshList) {
          agents = readAgents(freshList, agents);
          hovered = null;
          layout();
          // Flash workers whose task emitted an event newer than any seen.
          // Skipped under reduced motion (the flash is animated).
          if (!reduce) {
            var byId = {};
            agents.forEach(function (a) { byId[a.id] = a; });
            var newMax = maxSeq;
            readEvents(doc.getElementById("office-events")).forEach(function (ev) {
              if (ev.seq > maxSeq) {
                if (byId[ev.task]) { byId[ev.task].flashUntil = nowMs + 1600; }
                if (ev.seq > newMax) { newMax = ev.seq; }
              }
            });
            maxSeq = newMax;
          } else {
            maxSeq = Math.max(maxSeq, maxSeqOf(readEvents(doc.getElementById("office-events"))));
            draw(0);
          }
        }
        var freshStatus = doc.querySelector(".status");
        var ourStatus = document.querySelector(".status");
        if (freshStatus && ourStatus) { ourStatus.textContent = freshStatus.textContent; }
        schedule();
      })
      .catch(function () { /* stop polling on error rather than loop on failure */ });
  }

  function boot() {
    layout();
    draw(0);
    if (!reduce) { window.requestAnimationFrame(draw); }
    schedule();
  }
  window.addEventListener("resize", function () { layout(); if (reduce) { draw(0); } });
  boot();
})();
