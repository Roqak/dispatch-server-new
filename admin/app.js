/* Dispatch admin panel — vanilla JS, no build step, no dependencies. */
(() => {
  "use strict";

  const TOKEN_KEY = "dispatch_admin_token";
  const ROLES = ["viewer", "editor", "creator", "admin"];
  const AUDIT_LIMIT = 500;

  const $ = (id) => document.getElementById(id);

  const els = {
    loginView: $("view-login"),
    appView: $("view-app"),
    loginForm: $("login-form"),
    loginEmail: $("login-email"),
    loginPassword: $("login-password"),
    loginPasswordLabel: $("login-password-label"),
    loginError: $("login-error"),
    loginSubmit: $("login-submit"),
    loginSub: $("login-sub"),
    loginTitle: $("login-title"),
    loginHost: $("login-host"),
    modeToggle: $("mode-toggle"),
    registerToggle: $("register-toggle"),
    logoutBtn: $("logout-btn"),
    meEmail: $("me-email"),
    meAvatar: $("me-avatar"),
    tabs: Array.from(document.querySelectorAll(".tab")),
    panels: { accounts: $("tab-accounts"), workspaces: $("tab-workspaces"), users: $("tab-users"), docs: $("tab-docs"), settings: $("tab-settings"), audit: $("tab-audit") },
    docsBody: $("docs-body"),
    docsCount: $("docs-count"),
    docsFoot: $("docs-foot"),
    docsRefresh: $("docs-refresh"),
    accountsCount: $("accounts-count"),
    accountsBody: $("accounts-body"),
    accountsTable: $("accounts-table"),
    accountsEmpty: $("accounts-empty"),
    accountsFoot: $("accounts-foot"),
    accountsRefresh: $("accounts-refresh"),
    accountAdd: $("account-add"),
    accountAddEmpty: $("account-add-empty"),
    secretNotice: $("secret-notice"),
    workspacesCount: $("workspaces-count"),
    workspacesBody: $("workspaces-body"),
    workspacesSearch: $("workspaces-search"),
    workspacesRefresh: $("workspaces-refresh"),
    workspacesFailed: $("workspaces-failed"),
    workspacesFailedText: $("workspaces-failed-text"),
    workspaceNew: $("workspace-new"),
    workspaceNewEmpty: $("workspace-new-empty"),
    keyNoticeGo: $("key-notice-go"),
    addForm: $("add-user-form"),
    newEmail: $("new-email"),
    newPassword: $("new-password"),
    newRole: $("new-role"),
    addOpen: $("add-user-open"),
    addCancel: $("add-user-cancel"),
    addError: $("add-user-error"),
    addUserSubmit: $("add-user-submit"),
    usersRefresh: $("users-refresh"),
    usersSearch: $("users-search"),
    usersCount: $("users-count"),
    usersBody: $("users-body"),
    regNotice: $("reg-notice"),
    regClose: $("reg-close"),
    keyNotice: $("key-notice"),
    settingsToggle: $("allow-registration"),
    auditRefresh: $("audit-refresh"),
    auditSearch: $("audit-search"),
    auditStatus: $("audit-status"),
    auditFoot: $("audit-foot"),
    auditBody: $("audit-body"),
    dialog: $("dialog"),
    dialogForm: $("dialog-form"),
    dialogTitle: $("dialog-title"),
    dialogBody: $("dialog-body"),
    dialogError: $("dialog-error"),
    dialogCancel: $("dialog-cancel"),
    dialogOk: $("dialog-ok"),
    toast: $("toast"),
  };

  let me = null;
  els.loginHost.textContent = "Server: " + location.host;
  let loginMode = "credentials";
  let toastTimer = null;
  let allUsers = [];
  let allAudit = [];
  let workspaces = null; // [{ id, name, type, accounts, dispatch? }] once listed; null if that failed
  let accounts = null; // connected Postman accounts once listed
  let canStoreKeys = true;

  /* ---- session storage ---- */

  const getToken = () => localStorage.getItem(TOKEN_KEY);
  const setToken = (token) => localStorage.setItem(TOKEN_KEY, token);
  const clearToken = () => localStorage.removeItem(TOKEN_KEY);

  /* ---- fetch wrapper ---- */

  async function api(path, options) {
    const opts = options || {};
    const headers = { Accept: "application/json" };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    const token = getToken();
    if (token) headers.Authorization = "Bearer " + token;

    let response;
    try {
      response = await fetch(path, {
        method: opts.method || "GET",
        headers,
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      });
    } catch (err) {
      return { ok: false, status: 0, error: "Network error: could not reach the server." };
    }

    let data = null;
    const text = await response.text();
    if (text) {
      try { data = JSON.parse(text); } catch (err) { data = null; }
    }

    if (!response.ok) {
      const message = data && typeof data === "object" && data.error
        ? String(data.error)
        : "Request failed with status " + response.status + ".";
      if (response.status === 401) {
        clearToken();
        showLogin();
      }
      return { ok: false, status: response.status, error: message };
    }
    return { ok: true, status: response.status, data };
  }

  /* ---- small DOM helpers ---- */

  function el(tag, className, content) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (content !== undefined && content !== null) node.textContent = String(content);
    return node;
  }

  function labeledCell(label, className, content) {
    const cell = el("td", className, content);
    cell.setAttribute("data-label", label);
    return cell;
  }

  // A table's empty, no-match or error state, in place of its rows. `opts`:
  // title, actions [{ label, onClick, primary }], retry (a loader, for errors).
  function statusRow(body, colSpan, text, opts) {
    const o = opts || {};
    body.textContent = "";
    const row = el("tr", "status-row");
    const cell = el("td", "empty-cell" + (o.retry ? " is-error" : ""));
    cell.colSpan = colSpan;
    const box = el("div", "empty");
    if (o.title) box.appendChild(el("strong", "empty-title", o.title));
    box.appendChild(el("p", "empty-text", text));
    const actions = (o.actions || []).slice();
    if (o.retry) actions.push({ label: "Try again", onClick: o.retry });
    if (actions.length) {
      const bar = el("div", "empty-actions");
      for (const a of actions) {
        const b = el("button", "btn" + (a.primary ? " primary" : ""), a.label);
        b.type = "button";
        b.addEventListener("click", a.onClick);
        bar.appendChild(b);
      }
      box.appendChild(bar);
    }
    cell.appendChild(box);
    row.appendChild(cell);
    body.appendChild(row);
  }

  function skeletonRows(body, colSpan) {
    if (body.querySelector("tr:not(.skeleton)") && body.children.length) return; // keep rows on refresh
    body.textContent = "";
    for (let i = 0; i < 3; i += 1) {
      const row = el("tr", "skeleton");
      const cell = el("td", "sk-" + (i + 1));
      cell.colSpan = colSpan;
      cell.appendChild(el("span", "skeleton-bar"));
      row.appendChild(cell);
      body.appendChild(row);
    }
  }

  /* ---- dialog ---- */

  // Native <dialog> brings focus trapping and Esc. `onSubmit` returns an error
  // string to keep the dialog open, or anything else to close and resolve with it.
  let dialogSubmit = null;
  let dialogDone = null;

  function openDialog({ title, body, okLabel, danger, onSubmit }) {
    els.dialogTitle.textContent = title;
    els.dialogBody.textContent = "";
    for (const node of body) els.dialogBody.appendChild(node);
    els.dialogError.hidden = true;
    els.dialogOk.textContent = okLabel;
    els.dialogOk.className = "btn " + (danger ? "danger-solid" : "primary");
    els.dialogOk.disabled = false;
    els.dialog.showModal();
    const focus = els.dialogBody.querySelector("input");
    if (focus) focus.focus();
    return new Promise((resolve) => {
      dialogSubmit = onSubmit;
      dialogDone = resolve;
    });
  }

  function closeDialog(value) {
    const done = dialogDone;
    dialogDone = null;
    dialogSubmit = null;
    if (els.dialog.open) els.dialog.close();
    if (done) done(value);
  }

  els.dialogForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!dialogSubmit) return;
    els.dialogOk.disabled = true;
    els.dialogError.hidden = true;
    const outcome = await dialogSubmit();
    els.dialogOk.disabled = false;
    if (outcome && outcome.error) {
      els.dialogError.textContent = outcome.error;
      els.dialogError.hidden = false;
      return;
    }
    closeDialog(true);
  });
  els.dialogCancel.addEventListener("click", () => closeDialog(null));
  els.dialog.addEventListener("cancel", () => closeDialog(null));

  /* ---- toast ---- */

  function toast(message, kind) {
    els.toast.textContent = message;
    els.toast.className = "toast " + (kind === "error" ? "error" : "ok") + " show";
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => els.toast.classList.remove("show"), kind === "error" ? 5000 : 2800);
  }

  const toastErr = (message) => toast(message, "error");
  const toastOk = (message) => toast(message, "ok");

  function fail(result) {
    toastErr(result && result.error ? result.error : "Request failed.");
  }

  /* ---- formatting ---- */

  function fmtTime(value) {
    if (value === null || value === undefined || value === "") return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  }

  const fmtDate = (value) => {
    const date = new Date(value);
    if (value === null || value === undefined || Number.isNaN(date.getTime())) return fmtTime(value);
    return date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  };

  const fmtStamp = (value) => {
    const date = new Date(value);
    if (value === null || value === undefined || Number.isNaN(date.getTime())) return fmtTime(value);
    return date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  function workspaceName(id) {
    const known = workspaces && workspaces.find((w) => w.id === id);
    if (!known) return id;
    const twins = workspaces.filter((w) => w.name === known.name).length;
    return twins > 1 && known.accounts.length ? known.name + " (" + known.accounts[0].label + ")" : known.name;
  }

  function grantsText(grants) {
    if (grants === null || grants === undefined) return "All workspaces";
    if (!grants.length) return "No workspaces";
    const names = grants.map(workspaceName);
    return names.length <= 2 ? names.join(", ") : names.length + " workspaces";
  }

  function statusClass(status) {
    const n = Number(status);
    if (!Number.isFinite(n)) return "";
    if (n >= 500) return "bad";
    if (n >= 400) return "warn";
    if (n >= 200 && n < 400) return "ok";
    return "";
  }

  /* ---- view switching ---- */

  function showInlineLoginError(message) {
    els.loginError.textContent = message;
    els.loginError.hidden = false;
  }

  function showLogin(message) {
    const wasInApp = !els.appView.hidden;
    me = null;
    els.appView.hidden = true;
    els.loginView.hidden = false;
    if (els.dialog.open) closeDialog(null);
    els.usersBody.textContent = "";
    els.auditBody.textContent = "";
    els.accountsBody.textContent = "";
    els.workspacesBody.textContent = "";
    accounts = null;
    workspaces = null;
    if (message !== undefined) showInlineLoginError(message);
    if (wasInApp) {
      els.loginPassword.value = "";
      try { els.loginEmail.focus(); } catch (err) { /* ignore */ }
    }
  }

  function showApp() {
    els.loginView.hidden = true;
    els.appView.hidden = false;
  }

  function switchTab(name) {
    if (!els.panels[name]) return;
    for (const tab of els.tabs) {
      const active = tab.dataset.tab === name;
      tab.classList.toggle("active", active);
      if (active) tab.setAttribute("aria-current", "page"); else tab.removeAttribute("aria-current");
    }
    if (location.hash.slice(1) !== name) history.replaceState(null, "", "#" + name);
    for (const key of Object.keys(els.panels)) els.panels[key].hidden = key !== name;
    if (name === "accounts") loadAccounts();
    else if (name === "workspaces") { loadUsers(); loadWorkspaces(); }
    else if (name === "users") loadUsers();
    else if (name === "docs") loadDocs();
    else if (name === "settings") loadSettings();
    else if (name === "audit") loadAudit();
  }

  for (const tab of els.tabs) {
    tab.addEventListener("click", () => switchTab(tab.dataset.tab));
  }

  /* ---- session flow ---- */

  // Every admin page load funnels through GET /me; admin API calls are only
  // made when /me reports role "admin".
  async function enterApp() {
    if (!getToken()) { showLogin(); return false; }
    const result = await api("/me");
    if (!result.ok) {
      if (result.status !== 401) { showLogin(); fail(result); }
      return false; // 401 was already routed to the login view by the wrapper
    }
    const user = result.data && result.data.user ? result.data.user : null;
    if (!user || user.role !== "admin") {
      clearToken();
      showLogin(user && user.id !== undefined
        ? "This account isn't an admin. Only the first account on a server is an admin automatically, so ask an admin to change your role."
        : "Sign-in failed.");
      return false;
    }
    me = user;
    els.meEmail.textContent = user.email || "Server admin";
    els.meEmail.title = user.email || "";
    els.meAvatar.textContent = (user.email || "A").charAt(0).toUpperCase();
    showApp();
    await loadAccounts();
    const start = location.hash.slice(1);
    switchTab(els.panels[start] ? start : accounts && accounts.length ? "users" : "accounts");
    loadWorkspaces();
    refreshRegistration();
    return true;
  }

  els.loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    els.loginError.hidden = true;
    els.loginError.textContent = "";
    const email = els.loginEmail.value.trim();
    const password = els.loginPassword.value;
    if (loginMode !== "admin" && (!email || !password)) {
      showInlineLoginError("Enter your email and password.");
      return;
    }
    if (loginMode === "admin" && !password) {
      showInlineLoginError("Enter the server admin password.");
      return;
    }
    els.loginSubmit.disabled = true;
    if (loginMode === "register") {
      const created = await api("/auth/register", { method: "POST", body: { email, password } });
      if (!created.ok) {
        els.loginSubmit.disabled = false;
        showInlineLoginError(created.status === 403
          ? "Registration is closed on this server. Ask an admin to add you."
          : created.error);
        return;
      }
    }
    const result = loginMode === "admin"
      ? await api("/auth/admin-login", { method: "POST", body: { password } })
      : await api("/auth/login", { method: "POST", body: { email, password } });
    els.loginSubmit.disabled = false;
    if (!result.ok) {
      showInlineLoginError(result.status === 403
        ? result.error + " This server may use a shared admin password instead."
        : result.error || "Sign-in failed.");
      return;
    }
    const token = result.data && result.data.token;
    if (!token) { showInlineLoginError("Sign-in did not return a token."); return; }
    setToken(token);
    setLoginMode("credentials");
    await enterApp();
  });

  function setLoginMode(mode) {
    loginMode = mode;
    const copy = {
      credentials: ["Manage Postman accounts, users and who can reach which workspace.", "Password", "Sign in", "current-password", "Sign in"],
      register: ["The first account on a new server becomes its admin. Create yours before anyone else can.", "Password", "Create account", "new-password", "Create the admin account"],
      admin: ["Use the password set in ADMIN_PASSWORD on this server.", "Admin password", "Sign in", "current-password", "Sign in with the admin password"],
    }[mode];
    els.loginTitle.textContent = copy[4];
    els.loginForm.dataset.mode = mode === "admin" ? "admin" : "credentials";
    els.loginSub.textContent = copy[0];
    els.loginPasswordLabel.textContent = copy[1];
    els.loginSubmit.textContent = copy[2];
    els.loginPassword.autocomplete = copy[3];
    els.loginPassword.placeholder = mode === "register" ? "At least 8 characters" : "";
    els.registerToggle.textContent = mode === "register" ? "Already have an account? Sign in" : "New server? Create the first account";
    els.registerToggle.hidden = mode === "admin";
    els.modeToggle.textContent = mode === "admin" ? "Use email and password instead" : "Use server admin password instead";
    els.modeToggle.hidden = mode === "register";
    els.loginError.hidden = true;
    els.loginError.textContent = "";
    try { (mode === "admin" ? els.loginPassword : els.loginEmail).focus(); } catch (err) { /* ignore */ }
  }

  els.modeToggle.addEventListener("click", () => setLoginMode(loginMode === "admin" ? "credentials" : "admin"));
  els.registerToggle.addEventListener("click", () => setLoginMode(loginMode === "register" ? "credentials" : "register"));

  els.logoutBtn.addEventListener("click", () => {
    // Best-effort revoke on the server (needs the Bearer header, so fire it
    // before dropping the token); outcome is irrelevant for the local logout.
    if (getToken()) { api("/auth/logout", { method: "POST" }); }
    clearToken();
    showLogin();
  });

  /* ---- Postman accounts ---- */

  const ACCOUNT_STATUS = {
    ok: ["ok", "Connected"],
    invalid: ["bad", "Key rejected"],
    unreachable: ["warn", "Can't reach Postman"],
    undecryptable: ["bad", "Can't read key"],
  };

  async function loadAccounts() {
    if (!accounts) skeletonRows(els.accountsBody, 6);
    const result = await api("/admin/postman-accounts");
    if (!result.ok) {
      if (result.status !== 401) { statusRow(els.accountsBody, 6, "Couldn't load Postman accounts.", { retry: () => loadAccounts() }); fail(result); }
      return;
    }
    accounts = result.data.accounts;
    canStoreKeys = result.data.can_store_keys;
    renderAccounts();
  }

  // Nothing to work in: no Postman account and no workspace stored here.
  function updateKeyNotice() {
    const noAccounts = Array.isArray(accounts) && !accounts.length;
    const stored = Array.isArray(workspaces) && workspaces.some((w) => w.dispatch);
    els.keyNotice.hidden = !(noAccounts && !stored);
  }

  function renderAccounts() {
    const empty = !accounts.length;
    els.accountsCount.textContent = empty ? "" : String(accounts.length);
    updateKeyNotice();
    els.secretNotice.hidden = canStoreKeys;
    els.accountsEmpty.hidden = !empty;
    els.accountsTable.hidden = empty;
    els.accountsFoot.hidden = empty;
    els.accountAdd.hidden = empty;
    els.accountsRefresh.hidden = empty;
    els.accountAdd.disabled = !canStoreKeys;
    els.accountAddEmpty.disabled = !canStoreKeys;
    els.accountsBody.textContent = "";
    for (const account of accounts) els.accountsBody.appendChild(accountRow(account));
  }

  function accountRow(account) {
    const row = el("tr");
    const name = labeledCell("Account");
    const nameWrap = el("span");
    nameWrap.appendChild(el("span", "acc-name", account.label));
    const sub = [];
    if (account.postman_name && account.postman_name !== account.label) sub.push(account.postman_name);
    if (account.region === "eu") sub.push("EU");
    if (account.source === "environment") sub.push("Set on the server");
    if (sub.length) nameWrap.appendChild(el("span", "acc-sub", sub.join(" · ")));
    name.appendChild(nameWrap);
    row.appendChild(name);

    row.appendChild(labeledCell("Key", "mono", account.key_hint));

    const reach = labeledCell("Workspaces");
    const reachBtn = el("button", "link", String(account.workspace_count));
    reachBtn.type = "button";
    reachBtn.setAttribute("aria-label", "See workspaces");
    reachBtn.addEventListener("click", () => switchTab("workspaces"));
    reach.appendChild(reachBtn);
    row.appendChild(reach);

    row.appendChild(labeledCell("API usage", "acc-usage",
      account.usage ? account.usage.used.toLocaleString() + " of " + account.usage.limit.toLocaleString() : "—"));

    const status = labeledCell("Status");
    const [kind, text] = ACCOUNT_STATUS[account.status] || ["", account.status];
    status.appendChild(el("span", "status " + kind, text));
    row.appendChild(status);

    const actions = labeledCell("Actions", "u-actions");
    const wrap = el("div", "action-row");
    if (account.source === "environment") {
      const note = el("span", "muted", "Managed by POSTMAN_API_KEY");
      wrap.appendChild(note);
    } else {
      const rename = el("button", "btn sm", "Rename");
      rename.type = "button";
      rename.addEventListener("click", () => renameAccountDialog(account));
      const replace = el("button", "btn sm", "Replace key");
      replace.type = "button";
      replace.disabled = !canStoreKeys;
      replace.addEventListener("click", () => replaceKeyDialog(account));
      const remove = el("button", "btn sm danger-ghost", "Remove");
      remove.type = "button";
      remove.addEventListener("click", () => removeAccountDialog(account));
      wrap.appendChild(rename);
      wrap.appendChild(replace);
      wrap.appendChild(remove);
    }
    actions.appendChild(wrap);
    row.appendChild(actions);
    return row;
  }

  function field(labelText, input, id) {
    const wrap = el("div", "field");
    const label = el("label", null, labelText);
    label.htmlFor = id;
    input.id = id;
    wrap.appendChild(label);
    wrap.appendChild(input);
    return wrap;
  }

  function keyInput() {
    const input = document.createElement("input");
    input.type = "password";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.placeholder = "PMAK-…";
    return input;
  }

  function addAccountDialog() {
    const key = keyInput();
    const label = document.createElement("input");
    label.type = "text";
    label.placeholder = "Uses the name on the Postman account";
    const region = document.createElement("select");
    for (const [value, text] of [["us", "United States"], ["eu", "Europe"]]) {
      const option = el("option", null, text);
      option.value = value;
      region.appendChild(option);
    }
    const help = el("p", "field-help");
    help.append("Create a key in ");
    const link = el("a", null, "Postman's API key settings");
    link.href = "https://go.postman.co/settings/me/api-keys";
    link.target = "_blank";
    link.rel = "noopener";
    help.append(link, ". Dispatch checks it with Postman, then stores it encrypted.");
    return openDialog({
      title: "Add a Postman account",
      okLabel: "Add account",
      body: [field("API key", key, "account-key"), field("Name (optional)", label, "account-label"), field("Postman region", region, "account-region"), help],
      onSubmit: async () => {
        if (!key.value.trim()) return { error: "Paste a Postman API key." };
        const result = await api("/admin/postman-accounts", {
          method: "POST",
          body: { api_key: key.value.trim(), label: label.value.trim(), region: region.value },
        });
        if (!result.ok) return { error: result.error };
        const count = result.data.workspace_count;
        toastOk("Connected " + result.data.label + ": " + count + (count === 1 ? " workspace." : " workspaces."));
        loadAccounts();
        loadWorkspaces();
        return null;
      },
    });
  }

  function renameAccountDialog(account) {
    const input = document.createElement("input");
    input.type = "text";
    input.value = account.label;
    return openDialog({
      title: "Rename " + account.label,
      okLabel: "Save",
      body: [field("Name", input, "account-rename")],
      onSubmit: async () => {
        const label = input.value.trim();
        if (!label) return { error: "Give the account a name." };
        const result = await api("/admin/postman-accounts/" + encodeURIComponent(account.id), { method: "PATCH", body: { label } });
        if (!result.ok) return { error: result.error };
        toastOk("Renamed to " + result.data.label + ".");
        loadAccounts();
        loadWorkspaces();
        return null;
      },
    });
  }

  function replaceKeyDialog(account) {
    const key = keyInput();
    return openDialog({
      title: "Replace the key for " + account.label,
      okLabel: "Replace key",
      body: [field("New API key", key, "account-new-key"), el("p", "field-help", "People's access stays the same. The old key stops being used here, but stays valid in Postman until you revoke it there.")],
      onSubmit: async () => {
        if (!key.value.trim()) return { error: "Paste a Postman API key." };
        const result = await api("/admin/postman-accounts/" + encodeURIComponent(account.id), { method: "PATCH", body: { api_key: key.value.trim() } });
        if (!result.ok) return { error: result.error };
        toastOk("Key replaced for " + account.label + ".");
        loadAccounts();
        loadWorkspaces();
        return null;
      },
    });
  }

  function removeAccountDialog(account) {
    return openDialog({
      title: "Remove " + account.label + "?",
      okLabel: "Remove account",
      danger: true,
      body: [el("p", "dialog-text muted", "People lose its " + account.workspace_count + " workspaces here, unless another connected account reaches them. Nothing changes in Postman, and the key stays valid there until you revoke it.")],
      onSubmit: async () => {
        const result = await api("/admin/postman-accounts/" + encodeURIComponent(account.id), { method: "DELETE" });
        if (!result.ok) return { error: result.error };
        toastOk("Removed " + account.label + ".");
        loadAccounts();
        loadWorkspaces();
        return null;
      },
    });
  }

  els.accountAdd.addEventListener("click", addAccountDialog);
  els.accountAddEmpty.addEventListener("click", addAccountDialog);
  els.accountsRefresh.addEventListener("click", () => { loadAccounts(); loadWorkspaces(); });
  els.keyNoticeGo.addEventListener("click", () => switchTab("workspaces"));

  /* ---- workspaces ---- */

  async function loadWorkspaces() {
    if (!workspaces) skeletonRows(els.workspacesBody, 4);
    const result = await api("/admin/workspaces");
    if (!result.ok || !result.data || !Array.isArray(result.data.workspaces)) {
      if (result.status !== 401) statusRow(els.workspacesBody, 4, "Couldn't load workspaces.", { retry: () => loadWorkspaces() });
      workspaces = null;
      return;
    }
    workspaces = result.data.workspaces;
    els.workspacesCount.textContent = workspaces.length ? String(workspaces.length) : "";
    const failed = result.data.failed_accounts || [];
    els.workspacesFailed.hidden = !failed.length;
    els.workspacesFailedText.textContent = failed.length
      ? "Couldn't list workspaces from " + failed.join(", ") + ", so some may be missing. Check Postman accounts."
      : "";
    renderWorkspaces();
    renderUsers();
    updateKeyNotice();
  }

  // People who can reach a workspace, split by how they got there.
  function membersOf(id) {
    const direct = allUsers.filter((u) => u.role !== "admin" && (u.workspace_grants || []).includes(id));
    const everywhere = allUsers.filter((u) => u.role === "admin" || u.workspace_grants === null || u.workspace_grants === undefined);
    return { direct, everywhere };
  }

  function renderWorkspaces() {
    if (!workspaces) return;
    els.workspacesBody.textContent = "";
    const query = els.workspacesSearch.value.trim().toLowerCase();
    const shown = workspaces.filter((w) => !query || w.name.toLowerCase().includes(query));
    if (!shown.length) {
      if (query) statusRow(els.workspacesBody, 4, "No workspaces match \u201c" + els.workspacesSearch.value.trim() + "\u201d.");
      else if (accounts && accounts.length) statusRow(els.workspacesBody, 4, "The connected Postman accounts don't have any workspaces yet. You can also create one stored on this server.", { title: "No workspaces in these accounts", actions: [{ label: "New workspace", primary: true, onClick: () => els.workspaceNew.click() }] });
      else statusRow(els.workspacesBody, 4, "Create one stored on this server, or connect a Postman account to bring in its workspaces.", { title: "No workspaces yet", actions: [{ label: "New workspace", primary: true, onClick: () => els.workspaceNew.click() }, { label: "Connect Postman", onClick: () => switchTab("accounts") }] });
      return;
    }
    for (const workspace of shown) {
      const row = el("tr");
      const name = labeledCell("Workspace");
      const wrap = el("span");
      wrap.appendChild(el("span", "acc-name", workspace.name));
      if (workspace.dispatch) wrap.appendChild(el("span", "acc-sub", contentsText(workspace)));
      else if (workspace.type) wrap.appendChild(el("span", "acc-sub", workspace.type === "personal" ? "Personal" : workspace.type === "team" ? "Team" : workspace.type));
      name.appendChild(wrap);
      row.appendChild(name);

      const through = labeledCell("Through");
      const pills = el("span");
      if (workspace.dispatch) pills.appendChild(el("span", "pill pill-server", "This server"));
      for (const account of workspace.accounts) pills.appendChild(el("span", "pill", account.label));
      through.appendChild(pills);
      row.appendChild(through);

      const { direct, everywhere } = membersOf(workspace.id);
      const parts = [];
      if (direct.length) parts.push(direct.length === 1 ? direct[0].email : direct.length + " people");
      const extra = everywhere.length;
      if (extra) parts.push(extra + " with all access");
      row.appendChild(labeledCell("Who has access", "muted", parts.join(", ")));

      const actions = labeledCell("Actions", "u-actions");
      const wrapBtn = el("div", "action-row");
      const manage = el("button", "btn sm", "Manage access");
      manage.type = "button";
      manage.addEventListener("click", () => workspaceAccessDialog(workspace));
      wrapBtn.appendChild(manage);
      if (workspace.dispatch) {
        const rename = el("button", "btn sm", "Rename");
        rename.type = "button";
        rename.addEventListener("click", () => renameWorkspaceDialog(workspace));
        wrapBtn.appendChild(rename);
        const remove = el("button", "btn sm danger-ghost", "Delete");
        remove.type = "button";
        remove.addEventListener("click", () => deleteWorkspaceDialog(workspace));
        wrapBtn.appendChild(remove);
      } else {
        const copy = el("button", "btn sm", "Copy to server");
        copy.type = "button";
        copy.title = "Store a copy of this workspace on this server";
        copy.addEventListener("click", () => importWorkspaceDialog(workspace));
        wrapBtn.appendChild(copy);
      }
      actions.appendChild(wrapBtn);
      row.appendChild(actions);
      els.workspacesBody.appendChild(row);
    }
  }

  function workspaceAccessDialog(workspace) {
    const list = el("div");
    const boxes = [];
    const rowFor = (user) => {
      const label = el("label", "check-row");
      const box = document.createElement("input");
      box.type = "checkbox";
      const everywhere = user.role === "admin" || user.workspace_grants === null || user.workspace_grants === undefined;
      box.checked = everywhere || (user.workspace_grants || []).includes(workspace.id);
      box.disabled = everywhere;
      if (!everywhere) boxes.push({ box, user });
      label.appendChild(box);
      label.appendChild(el("span", null, user.email || String(user.id)));
      label.appendChild(el("span", "note", user.role === "admin" ? "Admin" : everywhere ? "All workspaces" : user.role));
      return label;
    };
    for (const user of allUsers) list.appendChild(rowFor(user));
    return openDialog({
      title: "Access to " + workspace.name,
      okLabel: "Save",
      body: [list.children.length ? list : el("p", "dialog-text muted", "No people yet. Add them under Users.")],
      onSubmit: async () => {
        for (const { box, user } of boxes) {
          const current = user.workspace_grants || [];
          if (box.checked === current.includes(workspace.id)) continue;
          const next = box.checked ? [...current, workspace.id] : current.filter((id) => id !== workspace.id);
          const result = await api("/admin/users/" + encodeURIComponent(user.id), { method: "PATCH", body: { workspace_grants: next } });
          if (!result.ok) {
            renderWorkspaces();
            renderUsers();
            return { error: "Couldn't update " + user.email + ": " + result.error };
          }
          user.workspace_grants = next;
        }
        renderWorkspaces();
        renderUsers();
        toastOk("Access updated for " + workspace.name + ".");
        return null;
      },
    });
  }

  const plural = (n, one, many) => n + " " + (n === 1 ? one : many);

  function contentsText(workspace) {
    return "Stored here · " + plural(workspace.collections || 0, "collection", "collections") + ", "
      + plural(workspace.environments || 0, "environment", "environments");
  }

  function textInput(value, placeholder) {
    const input = document.createElement("input");
    input.type = "text";
    input.value = value || "";
    input.maxLength = 120;
    if (placeholder) input.placeholder = placeholder;
    return input;
  }

  function newWorkspaceDialog() {
    const input = textInput("", "Payments API");
    return openDialog({
      title: "New workspace on this server",
      okLabel: "Create workspace",
      body: [
        field("Name", input, "workspace-new-name"),
        el("p", "field-help", "Its collections, environments and global variables are stored in this server's database, not in Postman. Give people access after it's created."),
      ],
      onSubmit: async () => {
        const name = input.value.trim();
        if (!name) return { error: "Give the workspace a name." };
        const result = await api("/admin/dispatch-workspaces", { method: "POST", body: { name } });
        if (!result.ok) return { error: result.error };
        toastOk("Created " + result.data.name + ".");
        if (els.panels.workspaces.hidden) switchTab("workspaces");
        await loadWorkspaces();
        return null;
      },
    });
  }

  function renameWorkspaceDialog(workspace) {
    const input = textInput(workspace.name);
    return openDialog({
      title: "Rename " + workspace.name,
      okLabel: "Save",
      body: [field("Name", input, "workspace-rename")],
      onSubmit: async () => {
        const name = input.value.trim();
        if (!name) return { error: "Give the workspace a name." };
        const result = await api("/admin/dispatch-workspaces/" + encodeURIComponent(workspace.id), { method: "PATCH", body: { name } });
        if (!result.ok) return { error: result.error };
        toastOk("Renamed to " + result.data.name + ".");
        await loadWorkspaces();
        return null;
      },
    });
  }

  function deleteWorkspaceDialog(workspace) {
    return openDialog({
      title: "Delete " + workspace.name + "?",
      okLabel: "Delete workspace",
      danger: true,
      body: [el("p", "dialog-text muted", "This permanently deletes its " + plural(workspace.collections || 0, "collection", "collections")
        + " and " + plural(workspace.environments || 0, "environment", "environments") + " from this server, for everyone. It can't be undone. Copies already open in someone's desktop app stay on their device.")],
      onSubmit: async () => {
        const result = await api("/admin/dispatch-workspaces/" + encodeURIComponent(workspace.id), { method: "DELETE" });
        if (!result.ok) return { error: result.error };
        toastOk("Deleted " + workspace.name + ".");
        await loadWorkspaces();
        return null;
      },
    });
  }

  function importWorkspaceDialog(workspace) {
    const input = textInput(workspace.name);
    return openDialog({
      title: "Copy " + workspace.name + " to this server",
      okLabel: "Copy workspace",
      body: [
        field("Name for the copy", input, "workspace-import-name"),
        el("p", "field-help", "Copies its collections, environments and global variables into a new workspace stored on this server. Nothing changes in Postman, and the two don't sync afterwards. Give people access to the copy once it's made."),
      ],
      onSubmit: async () => {
        const name = input.value.trim();
        if (!name) return { error: "Give the copy a name." };
        els.dialogOk.textContent = "Copying…";
        const result = await api("/admin/dispatch-workspaces/import", { method: "POST", body: { workspace_id: workspace.id, name } });
        els.dialogOk.textContent = "Copy workspace";
        if (!result.ok) return { error: result.error };
        toastOk("Copied " + plural(result.data.collections, "collection", "collections") + " and "
          + plural(result.data.environments, "environment", "environments") + " into " + result.data.name + ".");
        await loadWorkspaces();
        return null;
      },
    });
  }

  els.workspaceNew.addEventListener("click", newWorkspaceDialog);
  els.workspaceNewEmpty.addEventListener("click", newWorkspaceDialog);
  els.workspacesSearch.addEventListener("input", renderWorkspaces);
  els.workspacesRefresh.addEventListener("click", () => { loadUsers(); loadWorkspaces(); });

  /* ---- users ---- */

  async function loadUsers() {
    skeletonRows(els.usersBody, 5);
    const result = await api("/admin/users");
    if (!result.ok) {
      if (result.status !== 401) { statusRow(els.usersBody, 5, "Couldn't load users.", { retry: () => loadUsers() }); fail(result); }
      return;
    }
    if (!Array.isArray(result.data)) { toastErr("Unexpected response from GET /admin/users."); return; }
    allUsers = result.data;
    els.usersCount.textContent = String(allUsers.length);
    renderUsers();
    renderWorkspaces();
  }

  function renderUsers() {
    els.usersBody.textContent = "";
    const query = els.usersSearch.value.trim().toLowerCase();
    const users = allUsers.filter((u) => !query || String(u.email || "").toLowerCase().includes(query));
    if (!users.length) {
      if (query) statusRow(els.usersBody, 5, "No users match \u201c" + els.usersSearch.value.trim() + "\u201d.");
      else statusRow(els.usersBody, 5, "Add people here, or let them register while registration is open.", { title: "No users yet", actions: [{ label: "Add user", primary: true, onClick: () => els.addOpen.click() }] });
      return;
    }
    for (const user of users) els.usersBody.appendChild(userRow(user));
  }

  els.usersSearch.addEventListener("input", renderUsers);

  function accessDialog(user) {
    const target = user.email || String(user.id);
    const grants = user.workspace_grants;
    const row = (input, text, note) => {
      const label = el("label", "check-row");
      label.appendChild(input);
      label.appendChild(el("span", null, text));
      if (note) label.appendChild(el("span", "note", note));
      return label;
    };
    const radio = (checked) => {
      const input = document.createElement("input");
      input.type = "radio";
      input.name = "access";
      input.checked = checked;
      return input;
    };
    const all = radio(grants === null || grants === undefined);
    const some = radio(!all.checked);
    const list = el("div", "access-list");
    const boxes = [];
    let idsInput = null;
    const body = [row(some, "Only selected workspaces"), row(all, "All workspaces, including ones added later")];
    if (workspaces && workspaces.length) {
      const known = workspaces.slice();
      for (const id of grants || []) if (!known.some((w) => w.id === id)) known.push({ id, name: id, accounts: [], missing: true });
      const groups = new Map();
      for (const w of known) {
        const group = w.missing ? "No longer reachable" : w.accounts[0].label;
        if (!groups.has(group)) groups.set(group, []);
        groups.get(group).push(w);
      }
      for (const [group, members] of groups) {
        const heading = groups.size > 1 ? el("div", "access-group", group) : null;
        if (heading) list.appendChild(heading);
        for (const w of members) {
          const box = document.createElement("input");
          box.type = "checkbox";
          box.value = w.id;
          box.checked = (grants || []).includes(w.id);
          box.addEventListener("change", () => { some.checked = true; });
          boxes.push(box);
          list.appendChild(row(box, w.name, w.accounts.length > 1 ? "also " + w.accounts.slice(1).map((a) => a.label).join(", ") : ""));
        }
      }
    } else {
      const field = el("div", "field");
      const label = el("label", null, "Workspace IDs, separated by commas");
      label.htmlFor = "access-ids";
      idsInput = document.createElement("input");
      idsInput.type = "text";
      idsInput.id = "access-ids";
      idsInput.spellcheck = false;
      idsInput.value = (grants || []).join(", ");
      idsInput.addEventListener("input", () => { some.checked = true; });
      field.appendChild(label);
      field.appendChild(idsInput);
      list.appendChild(field);
    }
    body.push(list);
    return openDialog({
      title: "Workspace access for " + target,
      okLabel: "Save",
      body,
      onSubmit: async () => {
        let next = null;
        if (some.checked) {
          next = idsInput
            ? idsInput.value.split(",").map((part) => part.trim()).filter(Boolean)
            : boxes.filter((b) => b.checked).map((b) => b.value);
        }
        const result = await api("/admin/users/" + encodeURIComponent(user.id), { method: "PATCH", body: { workspace_grants: next } });
        if (!result.ok) return { error: result.error };
        user.workspace_grants = next;
        renderUsers();
        renderWorkspaces();
        toastOk("Workspace access updated for " + target + ".");
        return null;
      },
    });
  }

  function passwordDialog(user) {
    const target = user.email || String(user.id);
    const field = el("div", "field");
    const label = el("label", null, "New password");
    label.htmlFor = "reset-password";
    const input = document.createElement("input");
    input.type = "password";
    input.id = "reset-password";
    input.autocomplete = "new-password";
    input.placeholder = "At least 8 characters";
    field.appendChild(label);
    field.appendChild(input);
    return openDialog({
      title: "Reset password for " + target,
      okLabel: "Reset password",
      body: [field],
      onSubmit: async () => {
        const password = input.value;
        if ([...password].length < 8) return { error: "Password must be at least 8 characters." };
        const result = await api("/admin/users/" + encodeURIComponent(user.id), { method: "PATCH", body: { password } });
        if (!result.ok) return { error: result.error };
        toastOk("Password updated for " + target + ".");
        return null;
      },
    });
  }

  function deleteDialog(user) {
    const target = user.email || String(user.id);
    return openDialog({
      title: "Delete " + target + "?",
      okLabel: "Delete user",
      danger: true,
      body: [el("p", "dialog-text muted", "They'll lose access immediately. This can't be undone.")],
      onSubmit: async () => {
        const result = await api("/admin/users/" + encodeURIComponent(user.id), { method: "DELETE" });
        if (!result.ok) return { error: result.error };
        toastOk("Deleted " + target + ".");
        loadUsers();
        return null;
      },
    });
  }

  function userRow(user) {
    const row = el("tr");
    const id = String(user.id);
    const isSelf = me !== null && String(me.id) === id;

    const emailCell = labeledCell("Email", "u-email");
    const emailMain = el("span", "u-email-main");
    emailMain.appendChild(el("span", null, user.email || id));
    if (isSelf) emailMain.appendChild(el("span", "you-badge", "You"));
    emailCell.appendChild(emailMain);

    const roleCell = labeledCell("Role", "u-role");
    const roleSelect = document.createElement("select");
    roleSelect.setAttribute("aria-label", "Role for " + (user.email || id));
    for (const role of ROLES) {
      const option = el("option", null, role.charAt(0).toUpperCase() + role.slice(1));
      option.value = role;
      roleSelect.appendChild(option);
    }
    roleSelect.value = typeof user.role === "string" ? user.role : "viewer";
    // The server allows it, but demoting yourself locks you out of this panel.
    roleSelect.disabled = isSelf;
    if (isSelf) roleSelect.title = "You can't change your own role.";
    roleSelect.addEventListener("change", async () => {
      const next = roleSelect.value;
      roleSelect.disabled = true;
      const result = await api("/admin/users/" + encodeURIComponent(id), { method: "PATCH", body: { role: next } });
      roleSelect.disabled = false;
      if (!result.ok) {
        roleSelect.value = typeof user.role === "string" ? user.role : "viewer";
        fail(result);
        return;
      }
      user.role = next;
      toastOk((user.email || id) + " is now " + next + ".");
    });
    roleCell.appendChild(roleSelect);

    const grantsCell = labeledCell("Workspace access", "u-grants");
    const isAdmin = user.role === "admin";
    const grantsBtn = el("button", "access-btn", isAdmin ? "All workspaces" : grantsText(user.workspace_grants));
    grantsBtn.type = "button";
    if (!isAdmin && user.workspace_grants && !user.workspace_grants.length) grantsBtn.classList.add("none");
    grantsBtn.disabled = isAdmin;
    if (isAdmin) grantsBtn.title = "Admins can always access every workspace.";
    grantsBtn.addEventListener("click", () => accessDialog(user));
    grantsCell.appendChild(grantsBtn);

    const createdCell = labeledCell("Created", "u-created muted", fmtDate(user.created_at));
    createdCell.title = fmtTime(user.created_at);

    const actionsCell = labeledCell("Actions", "u-actions");
    const actionsRow = el("div", "action-row");

    const resetBtn = el("button", "btn sm", "Reset password");
    resetBtn.type = "button";
    resetBtn.addEventListener("click", () => passwordDialog(user));

    const deleteBtn = el("button", "btn sm danger-ghost", "Delete");
    deleteBtn.type = "button";
    deleteBtn.disabled = isSelf;
    if (isSelf) deleteBtn.title = "You can't delete your own account.";
    deleteBtn.addEventListener("click", () => deleteDialog(user));

    actionsRow.appendChild(resetBtn);
    actionsRow.appendChild(deleteBtn);
    actionsCell.appendChild(actionsRow);

    row.appendChild(emailCell);
    row.appendChild(roleCell);
    row.appendChild(grantsCell);
    row.appendChild(createdCell);
    row.appendChild(actionsCell);
    return row;
  }

  function showAddForm(open) {
    els.addForm.hidden = !open;
    els.addOpen.hidden = open;
    els.addError.hidden = true;
    if (open) els.newEmail.focus();
  }

  els.addOpen.addEventListener("click", () => showAddForm(true));
  els.addCancel.addEventListener("click", () => showAddForm(false));

  els.addForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = els.newEmail.value.trim();
    const password = els.newPassword.value;
    const inlineError = (message) => { els.addError.textContent = message; els.addError.hidden = false; };
    if (!email || !password) { inlineError("Enter an email and a password."); return; }
    els.addError.hidden = true;
    els.addUserSubmit.disabled = true;
    const result = await api("/admin/users", { method: "POST", body: { email, password, role: els.newRole.value } });
    els.addUserSubmit.disabled = false;
    if (!result.ok) { inlineError(result.error); return; }
    els.newEmail.value = "";
    els.newPassword.value = "";
    els.newRole.value = "viewer";
    showAddForm(false);
    toastOk("User " + email + " created.");
    await loadUsers();
    // Nobody but an admin reaches anything until granted, so ask straight away.
    const created = allUsers.find((u) => u.id === result.data.id);
    if (created && created.role !== "admin" && workspaces && workspaces.length) accessDialog(created);
  });

  els.usersRefresh.addEventListener("click", () => { loadUsers(); loadWorkspaces(); });

  /* ---- documentation sites ---- */

  const DOCS_STATUS = { none: "No domain", pending: "Not verified", verified: "Verified", failed: "Verification failed" };

  async function loadDocs() {
    skeletonRows(els.docsBody, 4);
    const result = await api("/docs-sites");
    if (!result.ok) {
      if (result.status !== 401) { statusRow(els.docsBody, 4, "Couldn't load documentation sites.", { retry: () => loadDocs() }); fail(result); }
      return;
    }
    renderDocs((result.data && result.data.sites) || []);
  }

  function renderDocs(sites) {
    els.docsBody.textContent = "";
    els.docsCount.textContent = sites.length ? String(sites.length) : "";
    els.docsFoot.hidden = !sites.length;
    if (!sites.length) {
      statusRow(els.docsBody, 4, "Sites are created in the Dispatch app: open a collection's menu and choose Documentation. They appear here so you can give each one a domain and put it online.", { title: "No documentation sites yet" });
      return;
    }
    for (const site of sites) {
      const row = el("tr");
      const name = labeledCell("Site");
      const wrap = el("span");
      wrap.appendChild(el("span", "acc-name", site.name));
      wrap.appendChild(el("span", "acc-sub", site.current_version ? "Version " + site.current_version : "Nothing published yet"));
      name.appendChild(wrap);
      row.appendChild(name);

      const domain = labeledCell("Domain", "mono", site.hostname || "—");
      if (site.hostname && site.domain_status !== "verified" && site.verify_token) {
        domain.appendChild(el("span", "acc-sub", "TXT _dispatch-docs." + site.hostname.split(":")[0] + " = " + site.verify_token));
      }
      row.appendChild(domain);

      const status = labeledCell("Status");
      status.appendChild(el("span", "pill" + (site.live ? " pill-server" : ""), site.live ? "Live" : DOCS_STATUS[site.domain_status] || site.domain_status));
      if (site.check_message) status.appendChild(el("span", "acc-sub", site.check_message));
      row.appendChild(status);

      const actions = labeledCell("Actions", "u-actions");
      const buttons = el("div", "action-row");
      const add = (label, cls, handler) => { const b = el("button", "btn sm" + (cls ? " " + cls : ""), label); b.type = "button"; b.addEventListener("click", handler); buttons.appendChild(b); return b; };
      add(site.hostname ? "Change domain" : "Add domain", "", () => docsDomainDialog(site));
      if (site.hostname) add("Verify", "", async (event) => {
        event.target.disabled = true;
        const result = await api("/admin/docs-sites/" + encodeURIComponent(site.id) + "/verify", { method: "POST" });
        event.target.disabled = false;
        if (!result.ok) { fail(result); return; }
        if (result.data.domain_status === "verified") toastOk("Domain verified."); else toastErr(result.data.check_message || "Not verified yet.");
        loadDocs();
      });
      if (site.domain_status === "verified" && site.current_version) add(site.online ? "Take offline" : "Go live", "", async () => {
        const result = await api("/admin/docs-sites/" + encodeURIComponent(site.id), { method: "PATCH", body: { online: !site.online } });
        if (!result.ok) { fail(result); return; }
        toastOk(site.online ? "The site is offline." : "The site is live.");
        loadDocs();
      });
      add("Delete", "danger-ghost", () => docsDeleteDialog(site));
      actions.appendChild(buttons);
      row.appendChild(actions);
      els.docsBody.appendChild(row);
    }
  }

  function docsDomainDialog(site) {
    const input = document.createElement("input");
    input.type = "text";
    input.value = site.hostname || "";
    input.placeholder = "docs.example.com";
    input.spellcheck = false;
    const label = field("Domain or subdomain", input, "docs-domain");
    const note = el("p", "muted", "Use a domain that only serves this documentation, not this server's own address. Changing it takes the site offline until the new domain is verified.");
    openDialog({
      title: "Documentation domain",
      body: [label, note],
      okLabel: "Save",
      onSubmit: async () => {
        const result = await api("/admin/docs-sites/" + encodeURIComponent(site.id), { method: "PATCH", body: { hostname: input.value.trim() || null } });
        if (!result.ok) return { error: result.error };
        toastOk(result.data.hostname ? "Domain saved. Point it at this server, then verify." : "Domain removed.");
        loadDocs();
        return true;
      },
    });
  }

  function docsDeleteDialog(site) {
    openDialog({
      title: "Delete " + site.name + "?",
      body: [el("p", null, "This removes the site and every published version. The collection itself isn't touched.")],
      okLabel: "Delete",
      danger: true,
      onSubmit: async () => {
        const result = await api("/admin/docs-sites/" + encodeURIComponent(site.id), { method: "DELETE" });
        if (!result.ok) return { error: result.error };
        toastOk("Site deleted.");
        loadDocs();
        return true;
      },
    });
  }

  els.docsRefresh.addEventListener("click", () => loadDocs());

  /* ---- settings ---- */

  function showRegistration(open) {
    els.settingsToggle.checked = open;
    els.regNotice.hidden = !open;
  }

  async function refreshRegistration() {
    const result = await api("/admin/settings");
    if (result.ok) showRegistration(Boolean(result.data && result.data.allow_registration));
  }

  async function loadSettings() {
    els.settingsToggle.disabled = true;
    const result = await api("/admin/settings");
    els.settingsToggle.disabled = false;
    if (!result.ok) {
      if (result.status !== 401) fail(result);
      return;
    }
    showRegistration(Boolean(result.data && result.data.allow_registration));
  }

  async function setRegistration(desired) {
    els.settingsToggle.disabled = true;
    els.regClose.disabled = true;
    const result = await api("/admin/settings", { method: "PATCH", body: { allow_registration: desired } });
    els.settingsToggle.disabled = false;
    els.regClose.disabled = false;
    if (!result.ok) {
      showRegistration(!desired);
      fail(result);
      return;
    }
    showRegistration(desired);
    toastOk(desired ? "Registration is open." : "Registration is off.");
  }

  els.settingsToggle.addEventListener("change", () => setRegistration(els.settingsToggle.checked));
  els.regClose.addEventListener("click", () => setRegistration(false));

  /* ---- audit ---- */

  async function loadAudit() {
    skeletonRows(els.auditBody, 5);
    const result = await api("/admin/audit?limit=" + AUDIT_LIMIT);
    if (!result.ok) {
      if (result.status !== 401) { statusRow(els.auditBody, 5, "Couldn't load the audit log.", { retry: () => loadAudit() }); fail(result); }
      return;
    }
    if (!Array.isArray(result.data)) { toastErr("Unexpected response from GET /admin/audit."); return; }
    allAudit = result.data;
    renderAudit();
  }

  function auditUser(entry) {
    if (entry.email) return entry.email;
    return entry.user_id !== null && entry.user_id !== undefined ? "#" + entry.user_id : "—";
  }

  function renderAudit() {
    els.auditBody.textContent = "";
    const query = els.auditSearch.value.trim().toLowerCase();
    const failedOnly = els.auditStatus.value === "failed";
    const entries = allAudit.filter((entry) => {
      if (failedOnly && !(Number(entry.status) >= 400)) return false;
      if (!query) return true;
      return [auditUser(entry), entry.action, entry.method, entry.path].join(" ").toLowerCase().includes(query);
    });
    els.auditFoot.textContent = allAudit.length >= AUDIT_LIMIT ? "Showing the latest " + AUDIT_LIMIT + " entries." : "";
    if (!entries.length) {
      if (allAudit.length) statusRow(els.auditBody, 5, "Nothing matches that filter.");
      else statusRow(els.auditBody, 5, "Requests made through this server, and changes to accounts, users and access, are recorded here.", { title: "No activity yet" });
      return;
    }
    for (const entry of entries) {
      const row = el("tr");
      const timeCell = labeledCell("Time", "a-time", fmtStamp(entry.ts));
      timeCell.title = fmtTime(entry.ts);
      row.appendChild(timeCell);
      row.appendChild(labeledCell("User", "a-user", auditUser(entry)));
      row.appendChild(labeledCell("Action", "a-action mono", entry.action || "—"));
      const request = ((entry.method || "?") + " " + (entry.path || "")).trim();
      row.appendChild(labeledCell("Request", "a-request mono", request));
      const statusCell = labeledCell("Status", "a-status");
      const badge = el("span", "status " + statusClass(entry.status),
        entry.status === null || entry.status === undefined ? "—" : String(entry.status));
      statusCell.appendChild(badge);
      row.appendChild(statusCell);
      els.auditBody.appendChild(row);
    }
  }

  els.auditSearch.addEventListener("input", renderAudit);
  els.auditStatus.addEventListener("change", renderAudit);
  els.auditRefresh.addEventListener("click", () => loadAudit());

  /* ---- boot ---- */

  (async () => {
    if (getToken()) {
      await enterApp();
    } else {
      showLogin();
    }
  })();
})();