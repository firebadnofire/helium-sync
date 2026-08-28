import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import "./style.css";

type BookmarkStatus = "missing" | "readable" | { invalid: string };
type Profile = {
  directory_name: string;
  display_name: string;
  path: string;
  bookmarks_path: string;
  bookmark_status: BookmarkStatus;
};
type DiscoveryReport = {
  installation: { executable: string | null; user_data_dir: string; source: string };
  profiles: Profile[];
};
type DiagnosticCheck = {
  name: string;
  ok: boolean;
  summary: string;
  details: string;
};
type DiagnosticReport = { checks: DiagnosticCheck[] };
type SyncProof = {
  object_id: string;
  namespace: string;
  revision: number;
  cursor: number;
  plaintext_matches: boolean;
};

const app = document.querySelector<HTMLDivElement>("#app")!;
app.innerHTML = `
  <header>
    <div>
      <p class="eyebrow">SELF-HOSTED PROFILE SYNC</p>
      <h1>Helium Sync</h1>
      <p class="subtitle">Encrypted bookmark export through your server. Live browser data remains read-only.</p>
    </div>
    <span id="connection-badge" class="badge idle">Not connected</span>
  </header>

  <nav aria-label="Application sections">
    <button class="tab active" data-tab="connection">Server connection</button>
    <button class="tab" data-tab="profiles">Profiles</button>
    <button class="tab" data-tab="diagnostics">Diagnostics</button>
  </nav>

  <main>
    <section id="connection" class="panel active">
      <div class="section-heading">
        <div><p class="eyebrow">TRANSPORT</p><h2>Connect securely</h2></div>
        <div class="segmented" role="group" aria-label="Transport mode">
          <button id="mode-https" class="active">HTTPS</button>
          <button id="mode-ssh">SSH</button>
        </div>
      </div>

      <form id="https-form" class="form-grid">
        <label class="wide">Hostname or URL<input id="https-url" value="https://localhost" required /></label>
        <label>Port<input id="https-port" type="number" min="1" max="65535" value="7500" required /></label>
        <label class="wide">API token<input id="https-token" type="password" autocomplete="off" minlength="32" required /></label>
        <label>Certificate mode
          <select id="certificate-mode">
            <option value="system">System trust</option>
            <option value="custom_ca">Custom CA</option>
            <option value="pinned">Pinned certificate / SPKI</option>
          </select>
        </label>
        <label class="wide conditional-cert">Certificate PEM
          <div class="input-action"><input id="certificate-path" /><button type="button" id="browse-certificate">Browse</button></div>
        </label>
        <label class="wide conditional-pin">Expected SPKI pin
          <div class="input-action"><input id="spki-pin" placeholder="sha256/..." /><button type="button" id="calculate-pin">Read certificate</button></div>
        </label>
        <label class="wide">Device name<input id="https-device" value="My Helium device" maxlength="128" required /></label>
        <div class="wide form-actions"><button class="primary" type="submit">Connect with HTTPS</button></div>
      </form>

      <form id="ssh-form" class="form-grid hidden">
        <label class="wide">SSH host<input id="ssh-host" required /></label>
        <label>SSH port<input id="ssh-port" type="number" min="1" max="65535" value="22" required /></label>
        <label>Username<input id="ssh-username" autocomplete="username" required /></label>
        <label class="wide">Private key
          <div class="input-action"><input id="ssh-key" required /><button type="button" id="browse-key">Browse</button></div>
        </label>
        <label class="wide">Private-key passphrase (optional)<input id="ssh-passphrase" type="password" autocomplete="off" /></label>
        <label class="wide">Remote socket<input id="ssh-socket" value="/run/helium-sync/server.sock" required /></label>
        <label class="wide">Helium Sync API token<input id="ssh-token" type="password" autocomplete="off" minlength="32" required /></label>
        <label class="wide">Confirmed host-key fingerprint (only after verification)<input id="ssh-fingerprint" placeholder="SHA256:..." /></label>
        <label class="wide">Device name<input id="ssh-device" value="My Helium device" maxlength="128" required /></label>
        <div class="wide form-actions"><button class="primary" type="submit">Connect through SSH</button></div>
      </form>

      <aside class="security-note"><strong>Fail-closed security</strong><span>There is no option to ignore certificate or SSH host-key errors. API tokens and sync keys are stored in the operating system credential store.</span></aside>
      <div class="recovery">
        <button id="reveal-recovery" type="button">Reveal recovery code</button>
        <div class="input-action"><input id="import-code" type="password" placeholder="hsync1: recovery code" /><button id="import-recovery" type="button">Import</button></div>
      </div>
    </section>

    <section id="profiles" class="panel">
      <div class="section-heading"><div><p class="eyebrow">LOCAL BROWSER</p><h2>Discovered profiles</h2></div><button id="refresh-profiles">Refresh</button></div>
      <p id="installation-summary" class="muted">Discovery has not run yet.</p>
      <div id="profile-list" class="cards"></div>
      <div class="proof-actions">
        <button id="run-synthetic" class="primary" disabled>Run synthetic encrypted round trip</button>
        <button id="run-bookmarks" disabled>Export and verify selected bookmarks</button>
      </div>
      <pre id="proof-result" class="result hidden"></pre>
    </section>

    <section id="diagnostics" class="panel">
      <div class="section-heading"><div><p class="eyebrow">CONNECTION HEALTH</p><h2>Diagnostics</h2></div></div>
      <div id="diagnostic-list" class="diagnostics"><p class="muted">Connect to a server to run diagnostics.</p></div>
    </section>
  </main>
  <div id="toast" role="status" aria-live="polite"></div>
`;

let connected = false;
let profiles: Profile[] = [];
let selectedProfile: string | null = null;

const byId = <T extends HTMLElement>(id: string) => document.querySelector<T>(`#${id}`)!;
const value = (id: string) => byId<HTMLInputElement>(id).value;
const selectValue = (id: string) => byId<HTMLSelectElement>(id).value;

document.querySelectorAll<HTMLButtonElement>(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab, .panel").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    byId(button.dataset.tab!).classList.add("active");
  });
});

byId("mode-https").addEventListener("click", () => setMode("https"));
byId("mode-ssh").addEventListener("click", () => setMode("ssh"));
function setMode(mode: "https" | "ssh") {
  byId("mode-https").classList.toggle("active", mode === "https");
  byId("mode-ssh").classList.toggle("active", mode === "ssh");
  byId("https-form").classList.toggle("hidden", mode !== "https");
  byId("ssh-form").classList.toggle("hidden", mode !== "ssh");
}

byId<HTMLSelectElement>("certificate-mode").addEventListener("change", updateCertificateFields);
function updateCertificateFields() {
  const mode = selectValue("certificate-mode");
  document.querySelectorAll(".conditional-cert").forEach((item) => item.classList.toggle("hidden", mode === "system"));
  document.querySelectorAll(".conditional-pin").forEach((item) => item.classList.toggle("hidden", mode !== "pinned"));
}
updateCertificateFields();

byId("browse-certificate").addEventListener("click", async () => {
  const path = await open({ multiple: false, directory: false, filters: [{ name: "PEM certificates", extensions: ["pem", "crt", "cer"] }] });
  if (typeof path === "string") byId<HTMLInputElement>("certificate-path").value = path;
});
byId("browse-key").addEventListener("click", async () => {
  const path = await open({ multiple: false, directory: false });
  if (typeof path === "string") byId<HTMLInputElement>("ssh-key").value = path;
});
byId("calculate-pin").addEventListener("click", async () => {
  try {
    byId<HTMLInputElement>("spki-pin").value = await invoke<string>("inspect_certificate", { path: value("certificate-path") });
    toast("SPKI pin calculated from the selected certificate.", false);
  } catch (error) { toast(String(error), true); }
});

byId<HTMLFormElement>("https-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await runConnection("connect_https", {
    url: value("https-url"), port: Number(value("https-port")), apiToken: value("https-token"),
    certificateMode: selectValue("certificate-mode"), certificatePath: value("certificate-path") || null,
    spkiPin: value("spki-pin") || null, deviceName: value("https-device"),
  });
});
byId<HTMLFormElement>("ssh-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await runConnection("connect_ssh", {
    host: value("ssh-host"), port: Number(value("ssh-port")), username: value("ssh-username"),
    privateKey: value("ssh-key"), privateKeyPassphrase: value("ssh-passphrase") || null,
    remoteSocket: value("ssh-socket"), apiToken: value("ssh-token"),
    trustedFingerprint: value("ssh-fingerprint") || null, deviceName: value("ssh-device"),
  });
});

async function runConnection(command: string, input: unknown) {
  setBusy(true);
  try {
    const report = await invoke<DiagnosticReport>(command, { input });
    connected = true;
    byId("connection-badge").textContent = "Connected";
    byId("connection-badge").className = "badge success";
    renderDiagnostics(report);
    updateActionState();
    toast("Secure connection established.", false);
  } catch (error) {
    connected = false;
    byId("connection-badge").textContent = "Connection failed";
    byId("connection-badge").className = "badge error";
    toast(String(error), true);
  } finally { setBusy(false); }
}

byId("refresh-profiles").addEventListener("click", discover);
async function discover() {
  try {
    const report = await invoke<DiscoveryReport>("discover_profiles");
    profiles = report.profiles;
    byId("installation-summary").textContent = `Helium data: ${report.installation.user_data_dir} · ${profiles.length} profile(s)`;
    renderProfiles();
  } catch (error) {
    profiles = [];
    byId("installation-summary").textContent = String(error);
    renderProfiles();
  }
}

function renderProfiles() {
  const list = byId("profile-list");
  list.replaceChildren();
  for (const profile of profiles) {
    const readable = profile.bookmark_status === "readable";
    const card = document.createElement("button");
    card.className = `profile-card${selectedProfile === profile.directory_name ? " selected" : ""}`;
    card.type = "button";
    const title = document.createElement("strong");
    title.textContent = profile.display_name;
    const path = document.createElement("span");
    path.textContent = profile.path;
    const status = document.createElement("em");
    status.className = readable ? "ok" : "warning";
    status.textContent = readable ? "Bookmarks readable" : bookmarkStatus(profile.bookmark_status);
    card.append(title, path, status);
    card.addEventListener("click", () => { selectedProfile = profile.directory_name; renderProfiles(); });
    list.append(card);
  }
  if (profiles.length === 0) list.textContent = "No Helium profiles were found.";
  updateActionState();
}

function bookmarkStatus(status: BookmarkStatus): string {
  if (status === "missing") return "Bookmarks file missing";
  if (status === "readable") return "Bookmarks readable";
  return `Bookmark parse failed: ${status.invalid}`;
}

function updateActionState() {
  byId<HTMLButtonElement>("run-synthetic").disabled = !connected;
  const selected = profiles.find((profile) => profile.directory_name === selectedProfile);
  byId<HTMLButtonElement>("run-bookmarks").disabled = !connected || selected?.bookmark_status !== "readable";
}

byId("run-synthetic").addEventListener("click", () => runProof("run_synthetic", {}));
byId("run-bookmarks").addEventListener("click", () => runProof("run_bookmarks", { profileDirectory: selectedProfile }));
async function runProof(command: string, args: Record<string, unknown>) {
  setBusy(true);
  try {
    const proof = await invoke<SyncProof>(command, args);
    const result = byId("proof-result");
    result.textContent = `${proof.namespace}\nObject ${proof.object_id}\nRevision ${proof.revision} · Cursor ${proof.cursor}\nDecrypted comparison: ${proof.plaintext_matches ? "MATCH" : "FAILED"}`;
    result.classList.remove("hidden");
    toast("Encrypted round trip verified.", false);
  } catch (error) { toast(String(error), true); }
  finally { setBusy(false); }
}

byId("reveal-recovery").addEventListener("click", async () => {
  if (!window.confirm("The recovery code decrypts all synchronized data. Keep it private. Reveal it now?")) return;
  try {
    const code = await invoke<string>("reveal_recovery_code");
    window.prompt("Copy this recovery code and store it securely:", code);
  } catch (error) { toast(String(error), true); }
});
byId("import-recovery").addEventListener("click", async () => {
  try {
    await invoke("import_recovery_code", { recoveryCode: value("import-code") });
    connected = false;
    updateActionState();
    toast("Recovery code imported. Reconnect to use the imported key.", false);
  } catch (error) { toast(String(error), true); }
});

function renderDiagnostics(report: DiagnosticReport) {
  const list = byId("diagnostic-list");
  list.replaceChildren();
  for (const check of report.checks) {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    const dot = document.createElement("span");
    dot.className = check.ok ? "status-dot ok" : "status-dot error";
    const text = document.createElement("span");
    text.textContent = `${check.name} — ${check.summary}`;
    const body = document.createElement("p");
    body.textContent = check.details;
    summary.append(dot, text);
    details.append(summary, body);
    list.append(details);
  }
}

function setBusy(busy: boolean) {
  document.querySelectorAll<HTMLButtonElement>("button").forEach((button) => {
    if (busy) button.dataset.wasDisabled = String(button.disabled);
    button.disabled = busy || button.dataset.wasDisabled === "true";
    if (!busy) delete button.dataset.wasDisabled;
  });
}
let toastTimer = 0;
function toast(message: string, isError: boolean) {
  const element = byId("toast");
  element.textContent = message;
  element.className = `show ${isError ? "error" : "success"}`;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => element.className = "", 6000);
}

void discover();
