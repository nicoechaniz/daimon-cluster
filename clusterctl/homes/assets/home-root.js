// Navigation stays inside the selected root's route map. No message grants
// access to a resource, owner operation or another home.
"use strict";
(() => {
  const frame = document.querySelector("iframe[data-root-routes]");
  if (!frame) return;
  let routes;
  try {
    routes = JSON.parse(frame.dataset.rootRoutes);
  } catch {
    return;
  }
  const panel = document.querySelector("#root-external");
  const capabilities = () =>
    frame.contentWindow.postMessage(
      { type: "home-root:capabilities", routes },
      "*",
    );
  frame.addEventListener("load", capabilities);
  window.addEventListener("message", (event) => {
    if (event.source !== frame.contentWindow || event.origin !== "null") return;
    if (event.data?.type === "home-root:ready") {
      capabilities();
      return;
    }
    if (event.data?.type === "home-root:route") {
      const path = event.data.path;
      if (typeof path !== "string" || !Object.hasOwn(routes, path)) return;
      const fragment = event.data.fragment ?? "";
      if (typeof fragment !== "string" || fragment.length >= 2048 || !/^(?:#[A-Za-z0-9/_-]*)?$/.test(fragment)) return;
      location.assign(path + fragment);
      return;
    }
    if (event.data?.type === "home-root:external" && panel) {
      let url;
      try {
        url = new URL(event.data.url);
      } catch {
        return;
      }
      if (
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.href.length > 2048
      )
        return;
      // A visible link requires a fresh user click; child scripts cannot open
      // external pages or credential operations automatically.
      const link = panel.querySelector("a");
      link.href = url.href;
      link.textContent = "Open " + url.hostname + " ↗";
      panel.hidden = false;
    }
  });
  panel?.querySelector("button").addEventListener("click", () => {
    panel.hidden = true;
  });
  capabilities();
})();
