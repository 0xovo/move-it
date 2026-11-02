/*
  Move It screens runtime.

  - Every screen is one .app. Its states are <section class="state" data-state="name">.
    MoveIt.setState("success") shows one state. The URL hash picks the start state (#success).
  - Lemurs: <div class="lemur" data-lemur="show|still|dance|wait"></div> become loaders.
    MoveIt.lemur(stateName) returns that state's loader, so progress can be fed in.
  - Live values: elements with data-bind="name" get text from MoveIt.bind({ name: value }).
  - Buttons carry data-action="name"; MoveIt.on("name", fn) handles them. In the mockup,
    actions with data-go="screen.html#state" just navigate, so the flow is clickable.
  - ?embed hides the dev bar (used by index.html).
*/
(function () {
  "use strict";
  const params = new URLSearchParams(location.search);
  const embed = params.has("embed");
  if (embed) document.body.classList.add("embed");

  const app = document.querySelector(".app");
  const states = [...app.querySelectorAll(".state")];
  const lemurs = {};
  const handlers = {};
  let onState = null;

  function setState(name) {
    if (!states.some((s) => s.dataset.state === name)) name = states[0].dataset.state;
    for (const s of states) s.hidden = s.dataset.state !== name;
    app.dataset.state = name;
    document.querySelectorAll(".dev button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.state === name)));
    if (onState) onState(name);
  }

  function bind(values) {
    for (const [k, v] of Object.entries(values)) {
      document.querySelectorAll('[data-bind="' + k + '"]').forEach((el) => { el.textContent = v; });
    }
  }

  // dev bar: screen name + one pill per state
  const dev = document.querySelector(".dev");
  if (dev && states.length > 1) {
    for (const s of states) {
      const b = document.createElement("button");
      b.textContent = s.dataset.label || s.dataset.state;
      b.dataset.state = s.dataset.state;
      b.addEventListener("click", () => { history.replaceState(null, "", "#" + s.dataset.state); setState(s.dataset.state); });
      dev.appendChild(b);
    }
  }

  app.addEventListener("click", (e) => {
    const el = e.target.closest("[data-action]");
    if (!el || el.disabled) return;
    const name = el.dataset.action;
    if (handlers[name]) return handlers[name](el, e);
    if (el.dataset.go && !embed) location.href = el.dataset.go;
    else if (el.dataset.state) setState(el.dataset.state);
  });

  if (window.moveitIcons) window.moveitIcons();

  const ready = Promise.all([...document.querySelectorAll("[data-lemur]")].map(async (el) => {
    const l = await MoveItLoader.create(el, { frames: window.MOVEIT_FRAMES, base: el.dataset.base || "../loader/frames/" });
    l.setMode(el.dataset.lemur);
    if (el.dataset.progress) l.setProgress(Number(el.dataset.progress));
    const st = el.closest(".state");
    lemurs[st ? st.dataset.state : "_"] = l;
  }));

  window.MoveIt = {
    setState, bind, ready,
    lemur: (state) => lemurs[state],
    on: (name, fn) => { handlers[name] = fn; },
    onState: (fn) => { onState = fn; },
  };

  window.addEventListener("hashchange", () => setState(location.hash.slice(1)));
  ready.then(() => setState(location.hash.slice(1)));
  setState(location.hash.slice(1));
})();
