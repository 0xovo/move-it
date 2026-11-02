/*
  Move It loader.

  The figure is an OUTLINE. White fill rises inside it as real progress
  advances, so the fill level IS the progress indicator. While it fills,
  the outline keeps switching dance frames; the fill level is measured on
  the shared canvas, so it carries across frame switches. At 100 percent
  the figure holds the finale pose as a solid white silhouette.

  Art lives in frames/ as outline + mask pairs listed in frames/manifest.js.
  Swap the art there; this file never changes for new frames.

  Usage:
    const loader = await MoveItLoader.create(el, { frames: window.MOVEIT_FRAMES, base: "frames/" });
    loader.setProgress(0.42);      // real progress, 0 to 1
    loader.setMode("wait");        // "dance" (default, fills with progress), "wait" (blocked state),
                                   // "show" (solid, dancing: welcome), "still" (solid finale pose: all done)
    loader.onDone = () => {};      // fires once when the figure is full
*/
(function () {
  "use strict";

  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function loadImage(src) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error("Loader frame missing: " + src));
      img.src = src;
    });
  }

  async function create(container, opts) {
    const m = opts.frames;
    const base = opts.base || "frames/";
    const W = m.canvas.width, H = m.canvas.height;
    const fillBottom = m.fill.bottom, fillTop = m.fill.top;

    const art = {};
    await Promise.all(Object.entries(m.frames).map(async ([name, f]) => {
      const [outline, mask] = await Promise.all([loadImage(base + f.outline), loadImage(base + f.mask)]);
      art[name] = { outline, mask };
    }));

    const canvas = document.createElement("canvas");
    canvas.className = "moveit-loader";
    canvas.style.width = "100%";
    canvas.style.aspectRatio = W + " / " + H;
    canvas.style.display = "block";
    canvas.setAttribute("role", "progressbar");
    canvas.setAttribute("aria-valuemin", "0");
    canvas.setAttribute("aria-valuemax", "100");
    container.appendChild(canvas);
    const ctx = canvas.getContext("2d");
    const fillCanvas = document.createElement("canvas");
    const fctx = fillCanvas.getContext("2d");

    const state = {
      target: 0, shown: 0, mode: "dance", surface: opts.surface || "wave",
      frameIdx: 0, lastSwitch: 0, slosh: 0, doneAt: 0, running: true,
    };
    const api = {
      onDone: null,
      setProgress(p) {
        p = Math.max(0, Math.min(1, Number(p) || 0));
        if (p < 1 && state.doneAt) state.doneAt = 0;
        state.target = p;
        canvas.setAttribute("aria-valuenow", String(Math.round(p * 100)));
      },
      setMode(mode) {
        if (mode !== state.mode) { state.mode = mode; state.frameIdx = 0; state.lastSwitch = 0; }
      },
      setSurface(s) { state.surface = s; },
      get frameName() { return currentName(); },
      get shownProgress() { return state.shown; },
      destroy() { state.running = false; ro.disconnect(); canvas.remove(); },
    };

    function list() { return state.mode === "wait" && m.wait && m.wait.length ? m.wait : m.dance; }
    function currentName() {
      if (state.doneAt || state.mode === "still") return m.finale;
      const l = list();
      return l[state.frameIdx % l.length];
    }

    function resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, 3);
      const cssW = canvas.clientWidth || W;
      const px = Math.round(cssW * dpr);
      const py = Math.round(px * H / W);
      if (canvas.width !== px) {
        canvas.width = fillCanvas.width = px;
        canvas.height = fillCanvas.height = py;
      }
    }
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    resize();

    let last = performance.now();
    function tick(now) {
      if (!state.running) return;
      const dt = Math.min(64, now - last);
      last = now;

      // Ease the shown level toward real progress. It never runs ahead of it.
      const k = 1 - Math.exp(-dt / 160);
      state.shown += (state.target - state.shown) * k;
      if (Math.abs(state.target - state.shown) < 0.0005) state.shown = state.target;

      if (state.target >= 1 && state.shown > 0.995 && !state.doneAt) {
        state.shown = 1;
        state.doneAt = now;
        if (api.onDone) setTimeout(api.onDone, 0);
      }

      // Switch poses on the beat. Waiting taps at the same tempo.
      const beat = (m.beatMs || 488) * (reduceMotion ? 2 : 1);
      if (!state.doneAt && now - state.lastSwitch >= beat) {
        if (state.lastSwitch) { state.frameIdx++; state.slosh = 1; }
        state.lastSwitch = now;
      }
      state.slosh *= Math.exp(-dt / 260);

      draw(now);
      requestAnimationFrame(tick);
    }

    function draw(now) {
      const cw = canvas.width, ch = canvas.height, s = cw / W;
      const frame = art[currentName()];
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, cw, ch);

      // A small settle when the figure becomes full.
      if (state.doneAt && !reduceMotion) {
        const t = (now - state.doneAt) / 420;
        if (t < 1) {
          const sc = 1 + 0.06 * Math.sin(Math.PI * t);
          ctx.translate(cw / 2, fillBottom * s);
          ctx.scale(sc, sc);
          ctx.translate(-cw / 2, -fillBottom * s);
        }
      }

      if (state.doneAt || state.mode === "show" || state.mode === "still") {
        ctx.drawImage(frame.mask, 0, 0, cw, ch);
        ctx.drawImage(frame.outline, 0, 0, cw, ch);
        return;
      }

      // Faint ghost of the empty shape, so the outline reads as a vessel.
      ctx.globalAlpha = 0.07;
      ctx.drawImage(frame.mask, 0, 0, cw, ch);
      ctx.globalAlpha = 1;

      // Fill: the water region, clipped to this frame's mask.
      if (state.shown > 0.001) {
        const level = fillBottom - state.shown * (fillBottom - fillTop);
        const waveOn = state.surface === "wave" && !reduceMotion;
        const amp = waveOn ? (2.2 * Math.sqrt(Math.sin(Math.PI * state.shown)) + 2.4 * state.slosh) : 0;
        const t = now / 1000;
        fctx.setTransform(1, 0, 0, 1, 0, 0);
        fctx.globalCompositeOperation = "source-over";
        fctx.clearRect(0, 0, cw, ch);
        fctx.drawImage(frame.mask, 0, 0, cw, ch);
        fctx.globalCompositeOperation = "source-in";
        fctx.fillStyle = "#fff";
        fctx.beginPath();
        fctx.moveTo(0, ch);
        for (let x = 0; x <= W; x += 4) {
          const y = level + amp * (0.6 * Math.sin(x * 0.075 + t * 3.1) + 0.4 * Math.sin(x * 0.13 - t * 2.3));
          fctx.lineTo(x * s, y * s);
        }
        fctx.lineTo(cw, ch);
        fctx.closePath();
        fctx.fill();
        fctx.globalCompositeOperation = "source-over";
        ctx.drawImage(fillCanvas, 0, 0);
      }

      ctx.drawImage(frame.outline, 0, 0, cw, ch);
    }

    requestAnimationFrame(tick);
    return api;
  }

  window.MoveItLoader = { create };
})();
