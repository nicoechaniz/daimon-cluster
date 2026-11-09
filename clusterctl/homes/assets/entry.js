"use strict";
const params = new URLSearchParams(location.hash.slice(1));
const payload = Object.fromEntries(params);
const status = document.getElementById("entry-status");
const retry = document.getElementById("entry-retry");
async function enter() {
  retry.hidden = true;
  try {
    if ([...params.keys()].length !== 3 || !payload.code || !payload.proof || !payload.return) throw Error();
    const response = await fetch("/access/entry", {method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)});
    if (!response.ok) throw Error();
    const result = await response.json();
    if (result.status !== "approved" || typeof result.return !== "string" || !result.return.startsWith("/") || result.return.startsWith("//")) throw Error();
    history.replaceState(null, "", "/access/entry");
    location.replace(result.return);
  } catch {
    status.textContent = "No pudimos abrir el enlace. Podes volver a intentar; si vencio, pedi uno nuevo.";
    retry.hidden = false;
  }
}
retry.addEventListener("click", enter);
enter();
