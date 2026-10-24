// tasks_poll.js -- B11b client-side adaptive polling for /app/tasks/detail.
//
// Served as an external same-origin file (never inline) because
// rendering.MandatoryContentSecurityPolicy sets script-src 'self' with no
// 'unsafe-inline' -- see internal/transport/http/gintransport/rendering/renderer.go.
//
// The server (internal/transport/http/gintransport/web/handler.go's
// ServeTaskDetail) only ever states the STARTING poll interval for a fresh
// page load via data-poll-interval-ms on #task-detail (initialPollIntervalMS,
// keyed off the rendered status Label: "Running"/"Settling" -> 2000ms,
// everything else -> 10000ms). All backoff/reset stepping after that lives
// entirely here, driven by data-projection-revision/data-event-revision --
// query.TaskDetail's same-named fields (see contracts.go) -- which this
// script compares across polls: either value changing resets to the fast end
// of the interval's sequence; five consecutive polls with BOTH values
// unchanged step to the next (slower) interval in the sequence.
(function () {
  "use strict";

  var el = document.getElementById("task-detail");
  if (!el) {
    return;
  }

  // baseSequenceFor picks the step ladder anchored on the server's stated
  // starting interval: the fast (2s) ladder for an in-flight run, the slow
  // (10s) ladder otherwise. Both ladders hold their starting interval for
  // STEP_LIMIT identical polls before stepping up, then cap at their own
  // final value rather than growing without bound.
  function baseSequenceFor(ms) {
    if (ms === "2000") {
      return [2000, 2000, 2000, 2000, 2000, 4000, 8000, 16000, 30000];
    }
    return [10000, 10000, 10000, 10000, 10000, 20000, 30000];
  }

  var sequence = baseSequenceFor(el.dataset.pollIntervalMs);
  var step = 0;
  var lastProjection = el.dataset.projectionRevision;
  var lastEvent = el.dataset.eventRevision;
  var timer = null;

  function scheduleNext() {
    var interval = sequence[Math.min(step, sequence.length - 1)];
    timer = window.setTimeout(poll, interval);
  }

  function poll() {
    fetch(window.location.href, { credentials: "same-origin" })
      .then(function (resp) {
        // A non-2xx (e.g. session expired, task now 404) stops polling
        // rather than looping on a failing request forever.
        if (!resp.ok) {
          throw new Error("poll response not ok: " + resp.status);
        }
        return resp.text();
      })
      .then(function (html) {
        var parsed = new DOMParser().parseFromString(html, "text/html");
        var fresh = parsed.getElementById("task-detail");
        var current = document.getElementById("task-detail");
        if (!fresh || !current) {
          return;
        }
        // Harness phase 3c decision 13: never replace the page under a
        // shown pending permission request. The operator allows only what
        // they were shown; a swap could change the request under their
        // cursor. Answering it (or reloading) moves on.
        if (current.querySelector("#harness-permission-pending")) {
          step++;
          scheduleNext();
          return;
        }
        var changed =
          fresh.dataset.projectionRevision !== lastProjection ||
          fresh.dataset.eventRevision !== lastEvent;
        current.replaceWith(fresh);
        el = fresh;
        if (changed) {
          step = 0;
          sequence = baseSequenceFor(fresh.dataset.pollIntervalMs);
          lastProjection = fresh.dataset.projectionRevision;
          lastEvent = fresh.dataset.eventRevision;
        } else {
          // scheduleNext clamps step to sequence.length - 1, so this can
          // grow unboundedly without ever indexing out of range.
          step++;
        }
        scheduleNext();
      })
      .catch(function () {
        // Swallow transport/parse failures silently and keep the last
        // rendered state on screen; scheduleNext still runs so a transient
        // failure (e.g. a momentary network blip) does not permanently stop
        // polling.
        scheduleNext();
      });
  }

  scheduleNext();

  // Stop polling once the page is being torn down so an in-flight timer
  // never fires a fetch against a document that is no longer live.
  window.addEventListener("pagehide", function () {
    if (timer !== null) {
      window.clearTimeout(timer);
    }
  });
})();
