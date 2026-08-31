import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import "./style.css";

type BookmarkStatus = "missing" | "readable" | { invalid: string };
type BookmarkStats = { bookmarks: number; folders: number; bytes: number };
type Profile = {
  directoryName: string;
  displayName: string;
  browserName: string;
  bookmarkStatus: BookmarkStatus;
  isDefault: boolean;
  autoSync: boolean;
  hasSavedCopy: boolean;
  stats: BookmarkStats | null;
};
type ProfileReport = { profiles: Profile[] };
type DiagnosticCheck = { name: string; ok: boolean; summary: string; details: string };
type DiagnosticReport = { checks: DiagnosticCheck[] };
type SyncFeedback = {
  action: "saved" | "loaded" | "synced";
  profileDirectory: string;
  profileName: string;
  stats: BookmarkStats;
  revision: number;
  conflicts: number;
  backupPath: string | null;
  message: string;
};
type LoginResult = { diagnostics: DiagnosticReport; sync: SyncFeedback | null };

const app = document.querySelector<HTMLDivElement>("#app")!;
app.innerHTML = `
  <header>
    <div>
      <p class="eyebrow">PRIVATE BOOKMARK SYNC</p>
      <h1>Helium Sync</h1>
      <p class="subtitle">Keep encrypted Helium bookmarks consistent across your devices.</p>
    </div>
    <span id="connection-badge" class="badge idle">Signed out</span>
  </header>

  <nav aria-label="Application sections">
    <button class="tab active" data-tab="profiles">Profiles</button>
    <button class="tab" data-tab="connection">Connection</button>
  </nav>

  <main>
    <section id="profiles" class="panel active">
      <div class="section-heading">
        <div><p class="eyebrow">LOCAL HELIUM</p><h2>Profiles</h2></div>
        <button id="refresh-profiles" type="button">Refresh</button>
      </div>
      <p class="muted profile-intro">Sync now or leave automatic sync enabled while this desktop client is open. Every local replacement is backed up first.</p>
      <div id="profile-list" class="profile-list" aria-live="polite"></div>
      <section id="sync-feedback" class="feedback hidden" aria-live="polite"></section>
    </section>

    <section id="connection" class="panel">
      <div class="section-heading">
        <div><p class="eyebrow">SERVER</p><h2>Sign in securely</h2></div>
        <div class="segmented" role="group" aria-label="Transport mode">
          <button id="mode-https" class="active" type="button">HTTPS</button>
          <button id="mode-ssh" type="button">SSH</button>
        </div>
      </div>
      <aside class="login-note">
        <strong>Sign in reconciles your default profile.</strong>
        <span>Local and server changes are merged. If the local Bookmarks file changes, its previous version is first backed up with Zstandard compression in Downloads.</span>
      </aside>

      <form id="https-form" class="form-grid">
        <label class="wide">Hostname or URL<input id="https-url" value="https://localhost" required /></label>
        <label>Port<input id="https-port" type="number" min="1" max="65535" value="7500" required /></label>
        <label class="wide">API token<input id="https-token" type="password" autocomplete="off" minlength="32" required /></label>
        <label>Certificate verification
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
        <div class="wide form-actions"><button class="primary" type="submit">Sign in and sync</button></div>
      </form>

      <form id="ssh-form" class="form-grid hidden">
        <label class="wide">SSH host<input id="ssh-host" required /></label>
        <label>SSH port<input id="ssh-port" type="number" min="1" max="65535" value="22" required /></label>
        <label>Username<input id="ssh-username" autocomplete="username" required /></label>
        <label class="wide">Private key (OpenSSH, PEM, or PuTTY .ppk)
          <div class="input-action"><input id="ssh-key" required /><button type="button" id="browse-key">Browse</button></div>
        </label>
        <label class="wide">Private-key passphrase (optional)<input id="ssh-passphrase" type="password" autocomplete="off" /></label>
        <label class="wide">Remote socket<input id="ssh-socket" value="/run/helium-sync/server.sock" required /></label>
        <label class="wide">Helium Sync API token<input id="ssh-token" type="password" autocomplete="off" minlength="32" required /></label>
        <label class="wide">Confirmed host-key fingerprint<input id="ssh-fingerprint" placeholder="SHA256:..." /></label>
        <label class="wide">Device name<input id="ssh-device" value="My Helium device" maxlength="128" required /></label>
        <div class="wide form-actions"><button class="primary" type="submit">Sign in and sync</button></div>
      </form>

      <details class="advanced">
        <summary>Security, recovery, and connection details</summary>
        <p class="muted">Certificate and SSH host-key validation always fail closed. Secrets are stored in the operating system credential store.</p>
        <div class="recovery">
          <button id="reveal-recovery" type="button">Reveal recovery code</button>
          <div class="input-action"><input id="import-code" type="password" placeholder="hsync1: recovery code" /><button id="import-recovery" type="button">Import</button></div>
        </div>
        <div id="diagnostic-list" class="diagnostics"><p class="muted">Sign in to see connection checks.</p></div>
      </details>
    </section>
  </main>
  <div id="toast" role="status" aria-live="polite"></div>
`;

let connected = false;
let profiles: Profile[] = [];
let selectedProfile: string | null = null;
const syncInProgress = new Set<string>();
const AUTOMATIC_SYNC_INTERVAL_MS = 30_000;

const byId = <T extends HTMLElement>(id: string) => document.querySelector<T>(`#${id}`)!;
const value = (id: string) => byId<HTMLInputElement>(id).value;
const selectValue = (id: string) => byId<HTMLSelectElement>(id).value;

document.querySelectorAll<HTMLButtonElement>(".tab").forEach((button) => {
  button.addEventListener("click", () => showTab(button.dataset.tab!));
});
function showTab(tab: string) {
  document.querySelectorAll(".tab, .panel").forEach((item) => item.classList.remove("active"));
  document.querySelector<HTMLButtonElement>(`.tab[data-tab="${tab}"]`)?.classList.add("active");
  byId(tab).classList.add("active");
}

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
  await runLogin("connect_https", {
    url: value("https-url"), port: Number(value("https-port")), apiToken: value("https-token"),
    certificateMode: selectValue("certificate-mode"), certificatePath: value("certificate-path") || null,
    spkiPin: value("spki-pin") || null, deviceName: value("https-device"),
  });
});
byId<HTMLFormElement>("ssh-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await runLogin("connect_ssh", {
    host: value("ssh-host"), port: Number(value("ssh-port")), username: value("ssh-username"),
    privateKey: value("ssh-key"), privateKeyPassphrase: value("ssh-passphrase") || null,
    remoteSocket: value("ssh-socket"), apiToken: value("ssh-token"),
    trustedFingerprint: value("ssh-fingerprint") || null, deviceName: value("ssh-device"),
  });
});

async function runLogin(command: string, input: unknown) {
  setBusy(true);
  try {
    const result = await invoke<LoginResult>(command, { input });
    connected = true;
    byId("connection-badge").textContent = "Signed in";
    byId("connection-badge").className = "badge success";
    renderDiagnostics(result.diagnostics);
    if (result.sync) renderFeedback(result.sync);
    await discover();
    showTab("profiles");
    toast(result.sync?.message ?? "Signed in. Choose a default profile to enable login sync.", false);
  } catch (error) {
    connected = false;
    byId("connection-badge").textContent = "Sign-in failed";
    byId("connection-badge").className = "badge error";
    toast(String(error), true);
  } finally { setBusy(false); }
}

byId("refresh-profiles").addEventListener("click", () => void discover());
async function discover() {
  try {
    const report = await invoke<ProfileReport>("discover_profiles");
    profiles = report.profiles;
    if (!profiles.some((profile) => profile.directoryName === selectedProfile)) {
      selectedProfile = profiles.find((profile) => profile.isDefault)?.directoryName ?? profiles[0]?.directoryName ?? null;
    }
    renderProfiles();
  } catch (error) {
    profiles = [];
    renderProfiles(String(error));
  }
}

function renderProfiles(error?: string) {
  const list = byId("profile-list");
  list.replaceChildren();
  if (error) {
    const message = document.createElement("p");
    message.className = "empty-state error-text";
    message.textContent = error;
    list.append(message);
    return;
  }
  if (profiles.length === 0) {
    const message = document.createElement("p");
    message.className = "empty-state";
    message.textContent = "No Helium profiles were found.";
    list.append(message);
    return;
  }

  for (const profile of profiles) {
    const readable = profile.bookmarkStatus === "readable";
    const selected = selectedProfile === profile.directoryName;
    const card = document.createElement("article");
    card.className = `profile-card${selected ? " selected" : ""}`;
    card.tabIndex = 0;
    card.addEventListener("click", (event) => {
      if ((event.target as HTMLElement).closest("button, input, label, summary, details")) return;
      selectedProfile = profile.directoryName;
      renderProfiles();
    });
    card.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectedProfile = profile.directoryName;
        renderProfiles();
      }
    });

    const selector = document.createElement("input");
    selector.type = "radio";
    selector.name = "selected-profile";
    selector.checked = selected;
    selector.ariaLabel = `Select ${profile.displayName}`;
    selector.addEventListener("change", () => { selectedProfile = profile.directoryName; renderProfiles(); });

    const identity = document.createElement("div");
    identity.className = "profile-identity";
    const titleRow = document.createElement("div");
    titleRow.className = "profile-title";
    const title = document.createElement("strong");
    title.textContent = profile.displayName;
    const rename = document.createElement("button");
    rename.type = "button";
    rename.className = "text-button";
    rename.textContent = "Rename";
    rename.addEventListener("click", () => void beginRename(profile, identity));
    titleRow.append(title, rename);
    const browserName = document.createElement("span");
    browserName.textContent = profile.browserName === profile.displayName
      ? `Helium ${profile.directoryName}`
      : `Helium name: ${profile.browserName} · ${profile.directoryName}`;
    const chips = document.createElement("div");
    chips.className = "chips";
    chips.append(
      chip(profile.isDefault ? "Default at sign-in" : "Manual", profile.isDefault ? "default" : ""),
      chip(profile.autoSync ? "Auto sync on" : "Auto sync off", profile.autoSync ? "saved" : ""),
      chip(profile.hasSavedCopy ? "Saved on server" : "Not saved yet", profile.hasSavedCopy ? "saved" : ""),
      chip(readable ? "Ready" : bookmarkStatus(profile.bookmarkStatus), readable ? "ready" : "warning"),
    );
    identity.append(titleRow, browserName, chips);

    const stats = document.createElement("div");
    stats.className = "profile-stats";
    stats.textContent = profile.stats
      ? `${profile.stats.bookmarks.toLocaleString()} bookmarks · ${profile.stats.folders.toLocaleString()} folders · ${formatBytes(profile.stats.bytes)}`
      : "Bookmark statistics unavailable";

    const actions = document.createElement("div");
    actions.className = "profile-actions";
    const makeDefault = document.createElement("button");
    makeDefault.type = "button";
    makeDefault.textContent = profile.isDefault ? "Default" : "Use at sign-in";
    makeDefault.disabled = profile.isDefault;
    makeDefault.addEventListener("click", () => void setDefault(profile));
    const autoSync = document.createElement("label");
    autoSync.className = "auto-sync-toggle";
    const autoSyncCheckbox = document.createElement("input");
    autoSyncCheckbox.type = "checkbox";
    autoSyncCheckbox.checked = profile.autoSync;
    autoSyncCheckbox.addEventListener("change", () => void setAutoSync(profile, autoSyncCheckbox.checked));
    autoSync.append(autoSyncCheckbox, document.createTextNode("Automatic"));
    const sync = document.createElement("button");
    sync.type = "button";
    sync.className = "primary";
    sync.textContent = "Sync now";
    sync.title = "Reconcile local and server bookmarks without discarding independent changes";
    sync.disabled = !connected || !readable || syncInProgress.has(profile.directoryName);
    sync.addEventListener("click", () => void runProfileAction("sync_profile", profile));
    const recovery = document.createElement("details");
    recovery.className = "profile-recovery";
    const recoverySummary = document.createElement("summary");
    recoverySummary.textContent = "Recovery";
    const save = document.createElement("button");
    save.type = "button";
    save.textContent = "Replace server copy";
    save.title = "Recovery action: replace the server copy with current local bookmarks";
    save.disabled = !connected || !readable;
    save.addEventListener("click", () => void runProfileAction("save_profile", profile));
    const load = document.createElement("button");
    load.type = "button";
    load.textContent = "Restore server copy";
    load.title = "Recovery action: back up local bookmarks, then replace them with the server copy";
    load.disabled = !connected || !profile.hasSavedCopy;
    load.addEventListener("click", () => void confirmLoad(profile));
    recovery.append(recoverySummary, save, load);
    actions.append(makeDefault, autoSync, sync, recovery);

    card.append(selector, identity, stats, actions);
    list.append(card);
  }
}

function chip(text: string, variant: string) {
  const element = document.createElement("span");
  element.className = `chip ${variant}`;
  element.textContent = text;
  return element;
}

async function beginRename(profile: Profile, container: HTMLElement) {
  const titleRow = container.querySelector(".profile-title")!;
  titleRow.replaceChildren();
  const input = document.createElement("input");
  input.value = profile.displayName;
  input.maxLength = 128;
  input.ariaLabel = "Profile name";
  const save = document.createElement("button");
  save.type = "button";
  save.textContent = "Save name";
  const submit = async () => {
    const name = input.value.trim();
    if (!name) { toast("Profile name cannot be empty.", true); return; }
    setBusy(true);
    try {
      const report = await invoke<ProfileReport>("rename_profile", { profileDirectory: profile.directoryName, displayName: name });
      profiles = report.profiles;
      renderProfiles();
      toast(`Renamed profile to ${name}.`, false);
    } catch (error) { toast(String(error), true); }
    finally { setBusy(false); }
  };
  save.addEventListener("click", () => void submit());
  input.addEventListener("keydown", (event) => { if (event.key === "Enter") void submit(); });
  titleRow.append(input, save);
  input.focus();
  input.select();
}

async function setDefault(profile: Profile) {
  setBusy(true);
  try {
    const report = await invoke<ProfileReport>("set_default_profile", { profileDirectory: profile.directoryName });
    profiles = report.profiles;
    selectedProfile = profile.directoryName;
    renderProfiles();
    toast(`${profile.displayName} will sync automatically when you sign in.`, false);
  } catch (error) { toast(String(error), true); }
  finally { setBusy(false); }
}

async function setAutoSync(profile: Profile, enabled: boolean) {
  try {
    const report = await invoke<ProfileReport>("set_profile_auto_sync", {
      profileDirectory: profile.directoryName,
      enabled,
    });
    profiles = report.profiles;
    renderProfiles();
    toast(`Automatic sync ${enabled ? "enabled" : "disabled"} for ${profile.displayName}.`, false);
  } catch (error) {
    toast(String(error), true);
    await discover();
  }
}

function confirmLoad(profile: Profile) {
  const confirmed = window.confirm(
    `Load the saved copy into ${profile.displayName}?\n\nThe current local Bookmarks file will first be backed up as a ZIP in Downloads. Close Helium before continuing so it cannot overwrite the restored file.`,
  );
  if (confirmed) void runProfileAction("load_profile", profile);
}

async function runProfileAction(
  command: "save_profile" | "load_profile" | "sync_profile",
  profile: Profile,
  background = false,
) {
  if (syncInProgress.has(profile.directoryName)) return;
  syncInProgress.add(profile.directoryName);
  if (!background) setBusy(true);
  try {
    const feedback = await invoke<SyncFeedback>(command, { profileDirectory: profile.directoryName });
    renderFeedback(feedback);
    await discover();
    if (!background) toast(feedback.message, false);
  } catch (error) { toast(String(error), true); }
  finally {
    syncInProgress.delete(profile.directoryName);
    if (!background) setBusy(false);
  }
}

async function runAutomaticSync() {
  if (!connected) return;
  const enabled = profiles.filter(
    (profile) => profile.autoSync && profile.bookmarkStatus === "readable",
  );
  for (const profile of enabled) {
    await runProfileAction("sync_profile", profile, true);
  }
}

function renderFeedback(feedback: SyncFeedback) {
  const panel = byId("sync-feedback");
  panel.replaceChildren();
  const title = document.createElement("strong");
  const action = feedback.action === "saved" ? "Saved"
    : feedback.action === "loaded" ? "Loaded"
      : "Synchronized";
  title.textContent = `${action} ${feedback.profileName}`;
  const summary = document.createElement("span");
  summary.textContent = `${feedback.stats.bookmarks.toLocaleString()} bookmarks · ${feedback.stats.folders.toLocaleString()} folders · ${formatBytes(feedback.stats.bytes)}`;
  panel.append(title, summary);
  if (feedback.backupPath) {
    const backup = document.createElement("span");
    backup.className = "backup-path";
    backup.textContent = `Local backup: ${feedback.backupPath}`;
    panel.append(backup);
  }
  panel.classList.remove("hidden");
}

function bookmarkStatus(status: BookmarkStatus): string {
  if (status === "missing") return "Bookmarks file missing";
  if (status === "readable") return "Ready";
  return `Invalid bookmarks: ${status.invalid}`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
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
    byId("connection-badge").textContent = "Signed out";
    byId("connection-badge").className = "badge idle";
    await discover();
    toast("Recovery code imported. Sign in again to use it.", false);
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
window.setInterval(() => void runAutomaticSync(), AUTOMATIC_SYNC_INTERVAL_MS);
