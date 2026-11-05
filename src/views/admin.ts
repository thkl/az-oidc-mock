import type { MockUser } from "../config.js";

/**
 * Renders the authenticated admin single-page UI.
 */
export function renderAdminPage(user: MockUser): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OIDC Admin</title>
  <script>
    try {
      const theme = localStorage.getItem("az_oidc_admin_theme") || "system";
      if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
    } catch {}
  </script>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #eaf4ff;
      --bg-start: #f8fbff;
      --bg-end: #dbeafe;
      --glow-a: rgba(59, 130, 246, .18);
      --glow-b: rgba(14, 165, 233, .15);
      --surface: rgba(255, 255, 255, .58);
      --surface-2: rgba(255, 255, 255, .72);
      --sidebar: rgba(255, 255, 255, .46);
      --field: rgba(255, 255, 255, .78);
      --button-bg: rgba(255, 255, 255, .52);
      --button-hover: rgba(255, 255, 255, .74);
      --glass-line: rgba(255, 255, 255, .58);
      --side-line: rgba(255, 255, 255, .42);
      --line: rgba(76, 129, 190, .24);
      --line-strong: rgba(49, 102, 175, .38);
      --text: #14345f;
      --muted: #527094;
      --primary: #2563eb;
      --primary-soft: rgba(37, 99, 235, .10);
      --danger: #dc2626;
      --focus: #1d4ed8;
      --shadow: 0 18px 52px rgba(37, 99, 235, .13);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-weight: 360;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0c1b33;
        --bg-start: #10233f;
        --bg-end: #071426;
        --glow-a: rgba(59, 130, 246, .22);
        --glow-b: rgba(125, 211, 252, .13);
        --surface: rgba(15, 32, 59, .58);
        --surface-2: rgba(25, 52, 88, .66);
        --sidebar: rgba(8, 20, 40, .48);
        --field: rgba(11, 25, 48, .70);
        --button-bg: rgba(255, 255, 255, .08);
        --button-hover: rgba(255, 255, 255, .13);
        --glass-line: rgba(191, 219, 254, .16);
        --side-line: rgba(191, 219, 254, .16);
        --line: rgba(147, 197, 253, .18);
        --line-strong: rgba(147, 197, 253, .34);
        --text: #e6f0ff;
        --muted: #9db7d6;
        --primary: #60a5fa;
        --primary-soft: rgba(96, 165, 250, .16);
        --danger: #f87171;
        --focus: #93c5fd;
        --shadow: 0 18px 52px rgba(2, 10, 24, .34);
      }
    }
    :root[data-theme="light"] {
      color-scheme: light;
      --bg: #eaf4ff;
      --bg-start: #f8fbff;
      --bg-end: #dbeafe;
      --glow-a: rgba(59, 130, 246, .18);
      --glow-b: rgba(14, 165, 233, .15);
      --surface: rgba(255, 255, 255, .58);
      --surface-2: rgba(255, 255, 255, .72);
      --sidebar: rgba(255, 255, 255, .46);
      --field: rgba(255, 255, 255, .78);
      --button-bg: rgba(255, 255, 255, .52);
      --button-hover: rgba(255, 255, 255, .74);
      --glass-line: rgba(255, 255, 255, .58);
      --side-line: rgba(255, 255, 255, .42);
      --line: rgba(76, 129, 190, .24);
      --line-strong: rgba(49, 102, 175, .38);
      --text: #14345f;
      --muted: #527094;
      --primary: #2563eb;
      --primary-soft: rgba(37, 99, 235, .10);
      --danger: #dc2626;
      --focus: #1d4ed8;
      --shadow: 0 18px 52px rgba(37, 99, 235, .13);
    }
    :root[data-theme="dark"] {
      color-scheme: dark;
      --bg: #0c1b33;
      --bg-start: #10233f;
      --bg-end: #071426;
      --glow-a: rgba(59, 130, 246, .22);
      --glow-b: rgba(125, 211, 252, .13);
      --surface: rgba(15, 32, 59, .58);
      --surface-2: rgba(25, 52, 88, .66);
      --sidebar: rgba(8, 20, 40, .48);
      --field: rgba(11, 25, 48, .70);
      --button-bg: rgba(255, 255, 255, .08);
      --button-hover: rgba(255, 255, 255, .13);
      --glass-line: rgba(191, 219, 254, .16);
      --side-line: rgba(191, 219, 254, .16);
      --line: rgba(147, 197, 253, .18);
      --line-strong: rgba(147, 197, 253, .34);
      --text: #e6f0ff;
      --muted: #9db7d6;
      --primary: #60a5fa;
      --primary-soft: rgba(96, 165, 250, .16);
      --danger: #f87171;
      --focus: #93c5fd;
      --shadow: 0 18px 52px rgba(2, 10, 24, .34);
    }
    * { box-sizing: border-box; }
    [v-cloak] { display: none; }
    body {
      margin: 0;
      min-height: 100dvh;
      background:
        radial-gradient(circle at 12% 8%, var(--glow-a), transparent 30%),
        radial-gradient(circle at 86% 18%, var(--glow-b), transparent 28%),
        linear-gradient(135deg, var(--bg-start) 0%, var(--bg) 45%, var(--bg-end) 100%);
      color: var(--text);
      font-weight: 360;
    }
    button, input, textarea, select { font: inherit; }
    button {
      min-height: 32px;
      border: 1px solid var(--line);
      border-radius: 5px;
      background: var(--button-bg);
      color: var(--text);
      padding: 5px 9px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 380;
      box-shadow: 0 1px 0 rgba(255, 255, 255, .55) inset;
      transition: border-color .16s ease, background .16s ease, box-shadow .16s ease;
    }
    button:hover { border-color: var(--line-strong); background: var(--button-hover); }
    button:focus-visible, input:focus-visible, textarea:focus-visible, select:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
    button.primary { background: linear-gradient(180deg, #3b82f6, #2563eb); border-color: rgba(37, 99, 235, .52); color: #fff; font-weight: 480; }
    button.danger { border-color: color-mix(in srgb, var(--danger), transparent 64%); color: var(--danger); }
    button[disabled] { opacity: .55; cursor: not-allowed; }
    input, textarea, select { width: 100%; min-height: 32px; border: 1px solid var(--line); border-radius: 5px; background: var(--field); color: var(--text); padding: 5px 8px; font-size: 12px; font-weight: 360; box-shadow: 0 1px 0 rgba(255, 255, 255, .40) inset; }
    textarea { min-height: 68px; resize: vertical; font-family: "Fira Code", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; line-height: 1.36; }
    label { display: grid; gap: 4px; color: var(--muted); font-size: 11px; font-weight: 430; }
    .shell { min-height: 100dvh; display: grid; grid-template-columns: minmax(240px, 300px) 1fr; }
    aside {
      border-right: 1px solid var(--side-line);
      background: var(--sidebar);
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      padding: 18px;
      display: grid;
      align-content: start;
      gap: 14px;
      box-shadow: 12px 0 44px rgba(37, 99, 235, .08);
    }
    main { min-width: 0; padding: 18px; display: grid; gap: 16px; align-content: start; }
    .brand { display: grid; gap: 4px; }
    .brand h1 { margin: 0; font-size: 18px; line-height: 1.2; font-weight: 480; letter-spacing: 0; }
    .brand p, .meta { margin: 0; color: var(--muted); font-size: 11px; line-height: 1.42; }
    .theme-control { display: grid; gap: 6px; }
    .theme-control span { color: var(--muted); font-size: 11px; font-weight: 430; }
    .segmented { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 4px; }
    .segmented button { min-height: 28px; padding: 4px 6px; }
    .segmented button[aria-pressed="true"] { border-color: var(--line-strong); background: var(--primary-soft); color: var(--text); }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      border: 1px solid var(--glass-line);
      border-radius: 8px;
      background: var(--surface);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      padding: 12px;
      box-shadow: var(--shadow);
    }
    .toolbar strong { font-weight: 480; }
    .actions { display: flex; flex-wrap: wrap; gap: 6px; }
    .tenant-list { display: grid; gap: 6px; }
    .tenant-tab { width: 100%; min-height: 0; display: grid; gap: 3px; text-align: left; padding: 8px; }
    .tenant-tab[aria-current="true"] { border-color: rgba(37, 99, 235, .42); background: var(--primary-soft); box-shadow: 0 8px 24px rgba(37, 99, 235, .10); }
    .tenant-tab span { font-weight: 460; }
    .tenant-tab small { color: var(--muted); overflow-wrap: anywhere; }
    .panel {
      border: 1px solid var(--glass-line);
      border-radius: 8px;
      background: var(--surface);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      box-shadow: var(--shadow);
    }
    .panel-header { padding: 9px 11px; border-bottom: 1px solid var(--line); display: flex; align-items: center; justify-content: space-between; gap: 10px; }
    .panel-header h2 { margin: 0; font-size: 14px; font-weight: 480; }
    .panel-body { padding: 11px; display: grid; gap: 10px; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .triple { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
    .split { display: grid; grid-template-columns: minmax(220px, 300px) 1fr; gap: 10px; }
    .secret-row { display: grid; grid-template-columns: 1fr auto auto; gap: 6px; align-items: end; }
    .row-list { display: grid; gap: 6px; align-content: start; }
    .row-button { min-height: 0; display: grid; gap: 3px; text-align: left; padding: 8px; }
    .row-button strong { font-weight: 440; }
    .row-button[aria-current="true"] { border-color: rgba(37, 99, 235, .42); background: var(--primary-soft); }
    .row-button small { color: var(--muted); overflow-wrap: anywhere; }
    .badges { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 2px; }
    .badge { display: inline-flex; align-items: center; min-height: 18px; border: 1px solid var(--line); border-radius: 999px; padding: 1px 6px; color: var(--muted); background: var(--button-bg); font-size: 10px; line-height: 1.4; font-weight: 430; }
    .badge.on { border-color: rgba(37, 99, 235, .38); color: var(--text); background: var(--primary-soft); }
    .checks { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
    .check { display: inline-flex; gap: 7px; align-items: center; color: var(--text); font-size: 12px; font-weight: 360; }
    .check input { width: 16px; min-height: 16px; }
    .share-box { display: grid; gap: 8px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2); padding: 9px; }
    .share-box strong { font-size: 12px; font-weight: 480; }
    .status { border-radius: 5px; padding: 7px 8px; font-size: 11px; border: 1px solid var(--line); color: var(--muted); background: var(--surface-2); }
    .status.ok { border-color: rgba(22, 101, 52, .26); color: #166534; background: rgba(220, 252, 231, .68); }
    :root[data-theme="dark"] .status.ok { color: #bbf7d0; background: rgba(20, 83, 45, .42); }
    .status.error { border-color: rgba(190, 18, 60, .28); color: #9f1239; background: rgba(255, 228, 230, .72); }
    :root[data-theme="dark"] .status.error { color: #fecdd3; background: rgba(76, 5, 25, .44); }
    .empty { color: var(--muted); border: 1px dashed var(--line-strong); border-radius: 8px; padding: 13px; background: var(--surface); }
    .mono { font-family: "Fira Code", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    @media (max-width: 900px) {
      .shell { grid-template-columns: 1fr; }
      aside { border-right: 0; border-bottom: 1px solid var(--line); }
      .split, .grid, .triple { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div id="app" class="shell" v-cloak>
    <aside>
      <div class="brand">
        <h1>OIDC Admin</h1>
        <p>Signed in as ${escapeHtml(user.preferred_username)}</p>
      </div>
      <div class="theme-control" aria-label="Theme">
        <span>Theme</span>
        <div class="segmented">
          <button type="button" :aria-pressed="themeMode === 'system'" @click="setTheme('system')">Auto</button>
          <button type="button" :aria-pressed="themeMode === 'light'" @click="setTheme('light')">Light</button>
          <button type="button" :aria-pressed="themeMode === 'dark'" @click="setTheme('dark')">Dark</button>
        </div>
      </div>
      <div class="actions">
        <button class="primary" type="button" @click="save" :disabled="saving || loading">Save</button>
        <button type="button" @click="load" :disabled="saving || loading">Reload</button>
      </div>
      <div v-if="status.message" class="status" :class="status.type" role="status">{{ status.message }}</div>
      <nav class="tenant-list" aria-label="Tenants">
        <button v-for="tenant in editable.tenants" :key="tenant.tenantId" class="tenant-tab" type="button" :aria-current="tenant.tenantId === selectedTenantId" @click="selectTenant(tenant.tenantId)">
          <span>{{ tenant.displayName || tenant.tenantId }}</span>
          <small class="mono">{{ tenant.tenantId }}</small>
        </button>
      </nav>
      <button type="button" @click="addTenant">Add Tenant</button>
    </aside>

    <main aria-live="polite">
      <div class="toolbar">
        <div>
          <strong>{{ selectedTenant ? selectedTenant.displayName : 'No tenant selected' }}</strong>
          <p class="meta">{{ editable.tenants.length }} tenants · {{ totalClients }} clients · {{ totalUsers }} users</p>
        </div>
        <div class="actions" v-if="selectedTenant">
          <button type="button" @click="duplicateTenant">Duplicate</button>
          <button class="danger" type="button" @click="removeTenant">Delete Tenant</button>
        </div>
      </div>

      <div v-if="loading" class="empty">Loading configuration...</div>
      <div v-else-if="!selectedTenant" class="empty">Create a tenant to begin.</div>
      <template v-else>
        <section class="panel" aria-labelledby="tenant-settings-title">
          <div class="panel-header">
            <h2 id="tenant-settings-title">Tenant Settings</h2>
          </div>
          <div class="panel-body">
            <div class="grid">
              <label>Tenant ID <input v-model.trim="selectedTenant.tenantId" @change="selectedTenantId = selectedTenant.tenantId"></label>
              <label>Display Name <input v-model.trim="selectedTenant.displayName"></label>
              <label>Session Lifetime Seconds <input v-model.number="selectedTenant.sessionLifetimeSeconds" type="number" min="1" step="1"></label>
              <label>Devices JSON <textarea v-model="selectedTenant.devicesText" spellcheck="false"></textarea></label>
            </div>
            <div class="checks">
              <label class="check"><input v-model="selectedTenant.secure" type="checkbox"> Secure login</label>
              <label class="check"><input v-model="selectedTenant.enableSessions" type="checkbox"> Login sessions</label>
              <label class="check"><input v-model="selectedTenant.twoFactorEnabled" type="checkbox"> 2FA enabled</label>
              <label class="check"><input v-model="selectedTenant.twoFactorMandatory" type="checkbox" @change="selectedTenant.twoFactorEnabled = selectedTenant.twoFactorEnabled || selectedTenant.twoFactorMandatory"> 2FA mandatory</label>
            </div>
            <div v-if="shareUserOptions.length" class="share-box">
              <strong>Shared Accounts</strong>
              <label>Source User
                <select v-model="selectedShareUserKey">
                  <option value="">Select a user</option>
                  <option v-for="option in shareUserOptions" :key="option.key" :value="option.key">{{ option.label }}</option>
                </select>
              </label>
              <label v-if="selectedShareUserKey" class="check">
                <input type="checkbox" :checked="isSelectedShareEnabled()" @change="setSelectedShare($event.target.checked)">
                Share selected user with this tenant
              </label>
            </div>
          </div>
        </section>

        <section class="panel" aria-labelledby="clients-title">
          <div class="panel-header">
            <h2 id="clients-title">Clients</h2>
            <button type="button" @click="addClient">Add Client</button>
          </div>
          <div class="panel-body split">
            <div class="row-list">
              <button v-for="(client, index) in selectedTenant.clients" :key="index" class="row-button" type="button" :aria-current="index === selectedClientIndex" @click="selectedClientIndex = index">
                <strong>{{ client.clientId || 'New client' }}</strong>
                <small>{{ client.redirectUris.length }} redirect URIs · {{ client.enabled ? 'enabled' : 'disabled' }}</small>
              </button>
            </div>
            <div v-if="selectedClient" class="panel-body">
              <div class="grid">
                <label>Client ID <input v-model.trim="selectedClient.clientId"></label>
                <div class="secret-row">
                  <label>Legacy Client Secret <input v-model="selectedClient.clientSecret" autocomplete="new-password"></label>
                  <button type="button" @click="generateClientSecret">Generate</button>
                </div>
              </div>
              <label>Named Client Secrets JSON <textarea v-model="selectedClient.clientSecretsText" spellcheck="false" placeholder='[{"name":"test","secret":"..."},{"name":"prod","secret":"..."}]'></textarea></label>
              <p class="meta">Each name is a separate accepted credential. Saved values are hidden; replace a masked value to change it.</p>
              <div class="checks">
                <label class="check"><input v-model="selectedClient.enabled" type="checkbox"> Enabled</label>
              </div>
              <label>Redirect URIs <textarea v-model="selectedClient.redirectUrisText" spellcheck="false"></textarea></label>
              <label>Allowed Scopes <textarea v-model="selectedClient.allowedScopesText" spellcheck="false"></textarea></label>
              <div class="actions"><button class="danger" type="button" @click="removeClient">Delete Client</button></div>
            </div>
            <div v-else class="empty">Select or add a client.</div>
          </div>
        </section>

        <section class="panel" aria-labelledby="users-title">
          <div class="panel-header">
            <h2 id="users-title">Users</h2>
            <button type="button" @click="addUser">Add User</button>
          </div>
          <div class="panel-body split">
            <div class="row-list">
              <button v-for="(user, index) in selectedTenant.users" :key="index" class="row-button" type="button" :aria-current="index === selectedUserIndex" @click="selectedUserIndex = index">
                <strong>{{ user.name || 'New user' }}</strong>
                <small>{{ user.preferred_username || user.email || user.sub }}</small>
              </button>
            </div>
            <div v-if="selectedUser" class="panel-body">
              <div class="grid">
                <label>Subject <input v-model.trim="selectedUser.sub"></label>
                <label>Name <input v-model.trim="selectedUser.name"></label>
                <label>Email <input v-model.trim="selectedUser.email" type="email"></label>
                <label>Preferred Username <input v-model.trim="selectedUser.preferred_username"></label>
              </div>
              <label>Roles <textarea v-model="selectedUser.rolesText" spellcheck="false"></textarea></label>
              <label>Claims JSON <textarea v-model="selectedUser.claimsText" spellcheck="false"></textarea></label>
              <div class="secret-row">
                <label>New Password <input v-model="selectedUser.newPassword" autocomplete="new-password" type="password"></label>
                <button type="button" @click="generateUserPassword">Generate</button>
                <button type="button" @click="setUserPassword" :disabled="!selectedUser.newPassword">Set</button>
              </div>
              <div class="actions">
                <button type="button" @click="resetUserMfa">Reset 2FA</button>
              </div>
              <div v-if="shareTargets.length" class="share-box">
                <strong>Share This User With</strong>
                <label v-for="tenant in shareTargets" :key="tenant.tenantId" class="check">
                  <input type="checkbox" :checked="isUserSharedWith(tenant)" @change="setUserShare(tenant, $event.target.checked)">
                  {{ tenant.displayName || tenant.tenantId }}
                </label>
              </div>
              <div class="actions"><button class="danger" type="button" @click="removeUser">Delete User</button></div>
            </div>
            <div v-else class="empty">Select or add a user.</div>
          </div>
        </section>
      </template>
    </main>
  </div>

  <script>
    // Creates a new tenant object with the same defaults as the server schema.
    const blankTenant = () => ({
      tenantId: 'tenant-' + Math.random().toString(36).slice(2, 7),
      displayName: 'New Tenant',
      clients: [],
      users: [],
      devices: [],
      sharedUsers: [],
      secure: false,
      enableSessions: true,
      sessionLifetimeSeconds: 28800,
      twoFactorEnabled: false,
      twoFactorMandatory: false,
      passkeysEnabled: false,
      passkeysMandatory: false
    });
    // Converts multiline or comma-separated admin text fields into string arrays.
    const splitLines = (value) => String(value || '').split(/\\r?\\n|,/).map((item) => item.trim()).filter(Boolean);
    // Converts scope text into token-like values split on whitespace or commas.
    const splitTokens = (value) => String(value || '').split(/[\\s,]+/).map((item) => item.trim()).filter(Boolean);
    // Produces a mutable copy without preserving references to the loaded config.
    const clone = (value) => JSON.parse(JSON.stringify(value));
    // Generates URL-safe random values for client secrets and suggested passwords.
    const randomBase64Url = (bytes) => {
      const data = new Uint8Array(bytes);
      crypto.getRandomValues(data);
      return btoa(String.fromCharCode(...data)).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '');
    };
    // Escapes text before rendering dynamic config values into HTML.
    const escapeText = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[char]);
    // Adds UI-only text fields and normalized booleans to the loaded config.
    const decorate = (config) => {
      const copy = clone(config);
      for (const tenant of copy.tenants) {
        tenant.devicesText = JSON.stringify(tenant.devices || [], null, 2);
        tenant.sharedUsers = tenant.sharedUsers || [];
        tenant.twoFactorEnabled = Boolean(tenant.twoFactorEnabled || tenant.twoFactorMandatory);
        tenant.twoFactorMandatory = Boolean(tenant.twoFactorMandatory);
        tenant.passkeysEnabled = Boolean(tenant.passkeysEnabled || tenant.passkeysMandatory);
        tenant.passkeysMandatory = Boolean(tenant.passkeysMandatory);
        for (const client of tenant.clients) {
          client.redirectUrisText = (client.redirectUris || []).join('\\n');
          client.allowedScopesText = (client.allowedScopes || []).join(' ');
          client.clientSecretsText = JSON.stringify(client.clientSecrets || [], null, 2);
        }
        for (const user of tenant.users) {
          user.rolesText = (user.roles || []).join('\\n');
          user.claimsText = JSON.stringify(user.claims || {}, null, 2);
          user.newPassword = '';
        }
      }
      return copy;
    };
    // Removes UI-only fields and converts text inputs back into persisted config shape.
    const clean = (config) => {
      const copy = clone(config);
      for (const tenant of copy.tenants) {
        tenant.devices = JSON.parse(tenant.devicesText || '[]');
        tenant.sharedUsers = tenant.sharedUsers || [];
        tenant.twoFactorEnabled = Boolean(tenant.twoFactorEnabled || tenant.twoFactorMandatory);
        tenant.twoFactorMandatory = Boolean(tenant.twoFactorMandatory);
        tenant.passkeysEnabled = Boolean(tenant.passkeysEnabled || tenant.passkeysMandatory);
        tenant.passkeysMandatory = Boolean(tenant.passkeysMandatory);
        delete tenant.devicesText;
        for (const client of tenant.clients) {
          client.redirectUris = splitLines(client.redirectUrisText);
          client.allowedScopes = splitTokens(client.allowedScopesText);
          client.clientSecrets = JSON.parse(client.clientSecretsText || '[]');
          if (!client.clientSecret) delete client.clientSecret;
          delete client.redirectUrisText;
          delete client.allowedScopesText;
          delete client.clientSecretsText;
        }
        for (const user of tenant.users) {
          user.roles = splitLines(user.rolesText);
          user.claims = JSON.parse(user.claimsText || '{}');
          delete user.rolesText;
          delete user.claimsText;
          delete user.newPassword;
        }
      }
      return copy;
    };

    // Holds all mutable browser-side UI state for the admin app.
    const state = {
      loading: true,
      saving: false,
      editable: { tenants: [] },
      selectedTenantId: '',
      selectedClientIndex: 0,
      selectedUserIndex: 0,
      selectedShareUserKey: '',
      csrfToken: '',
      authStatus: {},
      themeMode: localStorage.getItem('az_oidc_admin_theme') || 'system',
      status: { type: '', message: '' }
    };
    // Selection helpers keep render/update handlers compact.
    const selectedTenant = () => state.editable.tenants.find((tenant) => tenant.tenantId === state.selectedTenantId) || state.editable.tenants[0];
    const selectedClient = () => selectedTenant()?.clients[state.selectedClientIndex];
    const selectedUser = () => selectedTenant()?.users[state.selectedUserIndex];
    const shareTargets = () => selectedTenant() && selectedUser() ? state.editable.tenants.filter((tenant) => tenant !== selectedTenant()) : [];
    const shareUserOptions = () => selectedTenant()
      ? state.editable.tenants.filter((tenant) => tenant !== selectedTenant()).flatMap((tenant) => tenant.users.map((user) => ({
        key: tenant.tenantId + ':' + user.sub,
        tenantId: tenant.tenantId,
        userSub: user.sub,
        label: (user.name || user.preferred_username || user.sub) + ' - ' + (tenant.displayName || tenant.tenantId)
      })))
      : [];
    // Reads the latest runtime 2FA/passkey status for a tenant user.
    const userAuthStatus = (tenant, user) => state.authStatus?.[tenant?.tenantId]?.[user?.sub] || { mfa: false, passkey: false };
    // Renders compact text badges so security state is visible without relying on color alone.
    const renderAuthBadges = (tenant, user) => {
      const status = userAuthStatus(tenant, user);
      return \`<span class="badges" aria-label="Security enrollment"><span class="badge \${status.mfa ? 'on' : ''}">\${status.mfa ? '2FA set' : 'No 2FA'}</span><span class="badge \${status.passkey ? 'on' : ''}">\${status.passkey ? 'Passkey set' : 'No passkey'}</span></span>\`;
    };
    // Re-renders the full admin app and rebinds handlers because the DOM is replaced.
    const render = () => {
      const tenant = selectedTenant();
      const client = selectedClient();
      const user = selectedUser();
      const totalClients = state.editable.tenants.reduce((sum, item) => sum + item.clients.length, 0);
      const totalUsers = state.editable.tenants.reduce((sum, item) => sum + item.users.length, 0);
      document.getElementById('app').innerHTML = \`
        <aside>
          <div class="brand"><h1>OIDC Admin</h1><p>Signed in as ${escapeHtml(user.preferred_username)}</p></div>
          <div class="theme-control" aria-label="Theme">
            <span>Theme</span>
            <div class="segmented">
              <button type="button" data-action="theme" data-theme="system" aria-pressed="\${state.themeMode === 'system'}">Auto</button>
              <button type="button" data-action="theme" data-theme="light" aria-pressed="\${state.themeMode === 'light'}">Light</button>
              <button type="button" data-action="theme" data-theme="dark" aria-pressed="\${state.themeMode === 'dark'}">Dark</button>
            </div>
          </div>
          <div class="actions">
            <button class="primary" type="button" data-action="save" \${state.saving || state.loading ? 'disabled' : ''}>Save</button>
            <button type="button" data-action="load" \${state.saving || state.loading ? 'disabled' : ''}>Reload</button>
            <button type="button" data-action="logout">Sign out</button>
          </div>
          \${state.status.message ? \`<div class="status \${escapeText(state.status.type)}" role="status">\${escapeText(state.status.message)}</div>\` : ''}
          <nav class="tenant-list" aria-label="Tenants">\${state.editable.tenants.map((item, index) => \`
            <button class="tenant-tab" type="button" data-action="select-tenant" data-index="\${index}" aria-current="\${item.tenantId === state.selectedTenantId}">
              <span>\${escapeText(item.displayName || item.tenantId)}</span>
              <small class="mono">\${escapeText(item.tenantId)}</small>
            </button>\`).join('')}</nav>
          <button type="button" data-action="add-tenant">Add Tenant</button>
        </aside>
        <main aria-live="polite">
          <div class="toolbar">
            <div><strong>\${escapeText(tenant ? tenant.displayName : 'No tenant selected')}</strong><p class="meta">\${state.editable.tenants.length} tenants · \${totalClients} clients · \${totalUsers} users</p></div>
            \${tenant ? '<div class="actions"><button type="button" data-action="duplicate-tenant">Duplicate</button><button class="danger" type="button" data-action="remove-tenant">Delete Tenant</button></div>' : ''}
          </div>
          \${state.loading ? '<div class="empty">Loading configuration...</div>' : (!tenant ? '<div class="empty">Create a tenant to begin.</div>' : renderTenant(tenant, client, user))}
        </main>\`;
      bind();
    };
    // Renders tenant settings plus the client and user editor panels.
    const renderTenant = (tenant, client, user) => \`
      <section class="panel" aria-labelledby="tenant-settings-title">
        <div class="panel-header"><h2 id="tenant-settings-title">Tenant Settings</h2></div>
        <div class="panel-body">
          <div class="grid">
            <label>Tenant ID <input data-field="tenant.tenantId" value="\${escapeText(tenant.tenantId)}"></label>
            <label>Display Name <input data-field="tenant.displayName" value="\${escapeText(tenant.displayName)}"></label>
            <label>Session Lifetime Seconds <input data-field="tenant.sessionLifetimeSeconds" type="number" min="1" step="1" value="\${Number(tenant.sessionLifetimeSeconds || 1)}"></label>
            <label>Devices JSON <textarea data-field="tenant.devicesText" spellcheck="false">\${escapeText(tenant.devicesText || '[]')}</textarea></label>
          </div>
          <div class="checks">
            <label class="check"><input data-field="tenant.secure" type="checkbox" \${tenant.secure ? 'checked' : ''}> Secure login</label>
            <label class="check"><input data-field="tenant.enableSessions" type="checkbox" \${tenant.enableSessions ? 'checked' : ''}> Login sessions</label>
            <label class="check"><input data-field="tenant.twoFactorEnabled" type="checkbox" \${tenant.twoFactorEnabled ? 'checked' : ''}> 2FA enabled</label>
            <label class="check"><input data-field="tenant.twoFactorMandatory" type="checkbox" \${tenant.twoFactorMandatory ? 'checked' : ''}> 2FA mandatory</label>
            <label class="check"><input data-field="tenant.passkeysEnabled" type="checkbox" \${tenant.passkeysEnabled ? 'checked' : ''}> Passkeys enabled</label>
            <label class="check"><input data-field="tenant.passkeysMandatory" type="checkbox" \${tenant.passkeysMandatory ? 'checked' : ''}> Passkeys mandatory</label>
          </div>
          \${renderSharedAccounts(tenant)}
        </div>
      </section>
      <section class="panel" aria-labelledby="clients-title">
        <div class="panel-header"><h2 id="clients-title">Clients</h2><button type="button" data-action="add-client">Add Client</button></div>
        <div class="panel-body split">
          <div class="row-list">\${tenant.clients.map((item, index) => \`<button class="row-button" type="button" data-action="select-client" data-index="\${index}" aria-current="\${index === state.selectedClientIndex}"><strong>\${escapeText(item.clientId || 'New client')}</strong><small>\${(item.redirectUris || []).length} redirect URIs · \${item.enabled ? 'enabled' : 'disabled'}</small></button>\`).join('')}</div>
          \${client ? renderClient(client) : '<div class="empty">Select or add a client.</div>'}
        </div>
      </section>
      <section class="panel" aria-labelledby="users-title">
        <div class="panel-header"><h2 id="users-title">Users</h2><button type="button" data-action="add-user">Add User</button></div>
        <div class="panel-body split">
          <div class="row-list">\${tenant.users.map((item, index) => \`<button class="row-button" type="button" data-action="select-user" data-index="\${index}" aria-current="\${index === state.selectedUserIndex}"><strong>\${escapeText(item.name || 'New user')}</strong><small>\${escapeText(item.preferred_username || item.email || item.sub)}</small>\${renderAuthBadges(tenant, item)}</button>\`).join('')}</div>
          \${user ? renderUser(tenant, user) : '<div class="empty">Select or add a user.</div>'}
        </div>
      </section>\`;
    // Renders controls for sharing users from other tenants into the selected tenant.
    const renderSharedAccounts = (tenant) => {
      const options = shareUserOptions();
      if (!options.length) return '';
      const reference = selectedShareReference();
      const enabled = reference && (tenant.sharedUsers || []).some((entry) => entry.tenantId === reference.tenantId && entry.userSub === reference.userSub);
      return \`<div class="share-box"><strong>Shared Accounts</strong><label>Source User <select data-field="selectedShareUserKey"><option value="">Select a user</option>\${options.map((option) => \`<option value="\${escapeText(option.key)}" \${option.key === state.selectedShareUserKey ? 'selected' : ''}>\${escapeText(option.label)}</option>\`).join('')}</select></label>\${state.selectedShareUserKey ? \`<label class="check"><input type="checkbox" data-action="selected-share" \${enabled ? 'checked' : ''}> Share selected user with this tenant</label>\` : ''}</div>\`;
    };
    // Renders the selected client's editable fields.
    const renderClient = (client) => \`<div class="panel-body">
      <div class="grid"><label>Client ID <input data-field="client.clientId" value="\${escapeText(client.clientId)}"></label><div class="secret-row"><label>Legacy Client Secret <input data-field="client.clientSecret" autocomplete="new-password" value="\${escapeText(client.clientSecret || '')}"></label><button type="button" data-action="generate-client-secret">Generate</button></div></div>
      <label>Named Client Secrets JSON <textarea data-field="client.clientSecretsText" spellcheck="false" placeholder='[{"name":"test","secret":"..."},{"name":"prod","secret":"..."}]'>\${escapeText(client.clientSecretsText || '[]')}</textarea></label>
      <p class="meta">Each name is a separate accepted credential. Saved values are hidden; replace a masked value to change it.</p>
      <div class="checks"><label class="check"><input data-field="client.enabled" type="checkbox" \${client.enabled ? 'checked' : ''}> Enabled</label></div>
      <label>Redirect URIs <textarea data-field="client.redirectUrisText" spellcheck="false">\${escapeText(client.redirectUrisText || '')}</textarea></label>
      <label>Allowed Scopes <textarea data-field="client.allowedScopesText" spellcheck="false">\${escapeText(client.allowedScopesText || '')}</textarea></label>
      <div class="actions"><button class="danger" type="button" data-action="remove-client">Delete Client</button></div>
    </div>\`;
    // Renders the selected user's editable fields and security actions.
    const renderUser = (tenant, user) => \`<div class="panel-body">
      <div class="share-box"><strong>Security Enrollment</strong>\${renderAuthBadges(tenant, user)}</div>
      <div class="grid"><label>Subject <input data-field="user.sub" value="\${escapeText(user.sub)}"></label><label>Name <input data-field="user.name" value="\${escapeText(user.name)}"></label><label>Email <input data-field="user.email" type="email" value="\${escapeText(user.email)}"></label><label>Preferred Username <input data-field="user.preferred_username" value="\${escapeText(user.preferred_username)}"></label></div>
      <label>Roles <textarea data-field="user.rolesText" spellcheck="false">\${escapeText(user.rolesText || '')}</textarea></label>
      <label>Claims JSON <textarea data-field="user.claimsText" spellcheck="false">\${escapeText(user.claimsText || '{}')}</textarea></label>
      <div class="secret-row"><label>New Password <input data-field="user.newPassword" autocomplete="new-password" type="password" value="\${escapeText(user.newPassword || '')}"></label><button type="button" data-action="generate-user-password">Generate</button><button type="button" data-action="set-user-password" \${user.newPassword ? '' : 'disabled'}>Set</button></div>
      <div class="actions"><button type="button" data-action="reset-user-mfa">Reset 2FA</button><button type="button" data-action="reset-user-passkeys">Reset Passkeys</button></div>
      \${renderShareTargets(tenant, user)}
      <div class="actions"><button class="danger" type="button" data-action="remove-user">Delete User</button></div>
    </div>\`;
    // Renders checkboxes that share the selected user into other tenants.
    const renderShareTargets = (tenant, user) => {
      const targets = shareTargets();
      if (!targets.length) return '';
      return \`<div class="share-box"><strong>Share This User With</strong>\${targets.map((target, index) => {
        const checked = (target.sharedUsers || []).some((entry) => entry.tenantId === tenant.tenantId && entry.userSub === user.sub);
        return \`<label class="check"><input type="checkbox" data-action="user-share" data-index="\${index}" \${checked ? 'checked' : ''}> \${escapeText(target.displayName || target.tenantId)}</label>\`;
      }).join('')}</div>\`;
    };
    // Re-attaches listeners after every render.
    const bind = () => {
      document.querySelectorAll('[data-field]').forEach((element) => element.addEventListener('change', updateField));
      document.querySelectorAll('[data-action]').forEach((element) => element.addEventListener('click', handleAction));
    };
    // Applies a changed form field to the editable state object.
    const updateField = (event) => {
      const field = event.currentTarget.dataset.field;
      const tenant = selectedTenant();
      const client = selectedClient();
      const user = selectedUser();
      const value = event.currentTarget.type === 'checkbox' ? event.currentTarget.checked : event.currentTarget.value;
      if (field === 'tenant.tenantId') { tenant.tenantId = value.trim(); state.selectedTenantId = tenant.tenantId; }
      if (field === 'tenant.displayName') tenant.displayName = value.trim();
      if (field === 'tenant.sessionLifetimeSeconds') tenant.sessionLifetimeSeconds = Number(value);
      if (field === 'tenant.devicesText') tenant.devicesText = value;
      if (field === 'tenant.secure') tenant.secure = value;
      if (field === 'tenant.enableSessions') tenant.enableSessions = value;
      if (field === 'tenant.twoFactorEnabled') tenant.twoFactorEnabled = value;
      if (field === 'tenant.twoFactorMandatory') { tenant.twoFactorMandatory = value; tenant.twoFactorEnabled = tenant.twoFactorEnabled || value; }
      if (field === 'tenant.passkeysEnabled') tenant.passkeysEnabled = value;
      if (field === 'tenant.passkeysMandatory') { tenant.passkeysMandatory = value; tenant.passkeysEnabled = tenant.passkeysEnabled || value; }
      if (field === 'client.clientId') client.clientId = value.trim();
      if (field === 'client.clientSecret') client.clientSecret = value;
      if (field === 'client.clientSecretsText') client.clientSecretsText = value;
      if (field === 'client.enabled') client.enabled = value;
      if (field === 'client.redirectUrisText') client.redirectUrisText = value;
      if (field === 'client.allowedScopesText') client.allowedScopesText = value;
      if (field === 'user.sub') user.sub = value.trim();
      if (field === 'user.name') user.name = value.trim();
      if (field === 'user.email') user.email = value.trim();
      if (field === 'user.preferred_username') user.preferred_username = value.trim();
      if (field === 'user.rolesText') user.rolesText = value;
      if (field === 'user.claimsText') user.claimsText = value;
      if (field === 'user.newPassword') user.newPassword = value;
      if (field === 'selectedShareUserKey') state.selectedShareUserKey = value;
      render();
    };
    // Dispatches toolbar/list/action button clicks to their behavior.
    const handleAction = async (event) => {
      const action = event.currentTarget.dataset.action;
      if (action === 'theme') return setTheme(event.currentTarget.dataset.theme);
      if (action === 'logout') { location.assign('/internal/oauth2/v2.0/logout?post_logout_redirect_uri=' + encodeURIComponent('/internal/admin')); return; }
      if (action === 'load') return load();
      if (action === 'save') return save();
      if (action === 'select-tenant') return selectTenant(Number(event.currentTarget.dataset.index));
      if (action === 'add-tenant') return addTenant();
      if (action === 'duplicate-tenant') return duplicateTenant();
      if (action === 'remove-tenant') return removeTenant();
      if (action === 'select-client') { state.selectedClientIndex = Number(event.currentTarget.dataset.index); return render(); }
      if (action === 'add-client') return addClient();
      if (action === 'generate-client-secret') { selectedClient().clientSecret = 'az_mock-sk_' + randomBase64Url(24); return render(); }
      if (action === 'remove-client') return removeClient();
      if (action === 'select-user') { state.selectedUserIndex = Number(event.currentTarget.dataset.index); return render(); }
      if (action === 'add-user') return addUser();
      if (action === 'generate-user-password') { selectedUser().newPassword = 'az_mock-pw_' + randomBase64Url(18); return render(); }
      if (action === 'set-user-password') return setUserPassword();
      if (action === 'reset-user-mfa') return resetUserMfa();
      if (action === 'reset-user-passkeys') return resetUserPasskeys();
      if (action === 'remove-user') return removeUser();
      if (action === 'user-share') return setUserShare(shareTargets()[Number(event.currentTarget.dataset.index)], event.currentTarget.checked);
      if (action === 'selected-share') return setSelectedShare(event.currentTarget.checked);
    };
    // Stores the selected theme preference and applies it to the document.
    const setTheme = (theme) => {
      state.themeMode = theme;
      if (theme === 'system') localStorage.removeItem('az_oidc_admin_theme');
      else localStorage.setItem('az_oidc_admin_theme', theme);
      if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
      else delete document.documentElement.dataset.theme;
      render();
    };
    // Loads the redacted config and CSRF token from the admin API.
    const load = async () => {
      state.loading = true; state.status = { type: '', message: '' }; render();
      try {
        const response = await fetch('/internal/admin/api/config');
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error_description || 'Unable to load config');
        state.editable = decorate(payload.config);
        state.authStatus = payload.authStatus || {};
        state.csrfToken = payload.csrfToken || '';
        state.selectedTenantId = state.editable.tenants[0]?.tenantId || '';
        state.selectedClientIndex = 0; state.selectedUserIndex = 0; state.selectedShareUserKey = '';
      } catch (error) {
        state.status = { type: 'error', message: error.message };
      } finally {
        state.loading = false; render();
      }
    };
    // Saves the edited config through the admin API.
    const save = async () => {
      state.saving = true; state.status = { type: '', message: '' }; render();
      try {
        const response = await fetch('/internal/admin/api/config', { method: 'PUT', headers: adminJsonHeaders(), body: JSON.stringify({ config: clean(state.editable) }) });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error_description || 'Unable to save config');
        state.editable = decorate(payload.config);
        state.authStatus = payload.authStatus || state.authStatus;
        state.status = { type: 'ok', message: 'Configuration saved.' };
      } catch (error) {
        state.status = { type: 'error', message: error.message };
      } finally {
        state.saving = false; render();
      }
    };
    // Selects a tenant and resets child selections.
    const selectTenant = (index) => {
      state.selectedTenantId = state.editable.tenants[index]?.tenantId || '';
      state.selectedClientIndex = 0; state.selectedUserIndex = 0; state.selectedShareUserKey = ''; render();
    };
    // Adds a tenant with one default client and one default user.
    const addTenant = () => {
      const tenant = decorate({ tenants: [blankTenant()] }).tenants[0];
      tenant.clients.push({ clientId: 'new-client', redirectUris: [], redirectUrisText: '', allowedScopes: ['openid', 'profile', 'email'], allowedScopesText: 'openid profile email', enabled: true });
      tenant.users.push({ sub: 'new-user', name: 'New User', email: 'user@example.test', preferred_username: 'user@example.test', roles: [], rolesText: '', claims: {}, claimsText: '{}' });
      state.editable.tenants.push(tenant);
      state.selectedTenantId = tenant.tenantId; render();
    };
    // Copies the selected tenant as a starting point for a new tenant.
    const duplicateTenant = () => {
      const tenant = clone(selectedTenant());
      tenant.tenantId += '-copy'; tenant.displayName += ' Copy';
      state.editable.tenants.push(tenant); state.selectedTenantId = tenant.tenantId; render();
    };
    // Removes the selected tenant after confirmation.
    const removeTenant = () => {
      if (!confirm('Delete this tenant from the config?')) return;
      state.editable.tenants = state.editable.tenants.filter((tenant) => tenant !== selectedTenant());
      state.selectedTenantId = state.editable.tenants[0]?.tenantId || ''; render();
    };
    // Adds a client to the selected tenant.
    const addClient = () => {
      selectedTenant().clients.push({ clientId: 'new-client', clientSecret: '', clientSecrets: [], clientSecretsText: '[]', redirectUris: [], redirectUrisText: '', allowedScopes: ['openid', 'profile', 'email'], allowedScopesText: 'openid profile email', enabled: true });
      state.selectedClientIndex = selectedTenant().clients.length - 1; render();
    };
    // Removes the selected client after confirmation.
    const removeClient = () => {
      if (!confirm('Delete this client?')) return;
      selectedTenant().clients.splice(state.selectedClientIndex, 1);
      state.selectedClientIndex = Math.max(0, state.selectedClientIndex - 1); render();
    };
    // Adds a user to the selected tenant.
    const addUser = () => {
      selectedTenant().users.push({ sub: 'new-user', name: 'New User', email: 'user@example.test', preferred_username: 'user@example.test', roles: [], rolesText: '', claims: {}, claimsText: '{}' });
      state.selectedUserIndex = selectedTenant().users.length - 1; render();
    };
    // Removes the selected user after confirmation.
    const removeUser = () => {
      if (!confirm('Delete this user?')) return;
      selectedTenant().users.splice(state.selectedUserIndex, 1);
      state.selectedUserIndex = Math.max(0, state.selectedUserIndex - 1); render();
    };
    // Sends the pending password field to the password API without saving it in config.
    const setUserPassword = async () => {
      const tenant = selectedTenant(); const user = selectedUser();
      if (!tenant || !user?.newPassword) return;
      try {
        const response = await fetch('/internal/admin/api/passwords', { method: 'POST', headers: adminJsonHeaders(), body: JSON.stringify({ tenant_id: tenant.tenantId, user_sub: user.sub, password: user.newPassword }) });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error_description || 'Unable to set password');
        user.newPassword = ''; state.status = { type: 'ok', message: 'Password updated.' };
      } catch (error) {
        state.status = { type: 'error', message: error.message };
      }
      render();
    };
    // Removes the selected user's TOTP enrollment.
    const resetUserMfa = async () => {
      const tenant = selectedTenant(); const user = selectedUser();
      if (!tenant || !user || !confirm('Reset the authenticator enrollment for this user?')) return;
      try {
        const response = await fetch('/internal/admin/api/mfa', { method: 'DELETE', headers: adminJsonHeaders(), body: JSON.stringify({ tenant_id: tenant.tenantId, user_sub: user.sub }) });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error_description || 'Unable to reset 2FA');
        setUserAuthStatus(tenant, user, { mfa: false });
        state.status = { type: 'ok', message: payload.deleted ? '2FA enrollment reset.' : 'No 2FA enrollment existed.' };
      } catch (error) {
        state.status = { type: 'error', message: error.message };
      }
      render();
    };
    // Removes all passkeys registered for the selected user.
    const resetUserPasskeys = async () => {
      const tenant = selectedTenant(); const user = selectedUser();
      if (!tenant || !user || !confirm('Reset all passkeys for this user?')) return;
      try {
        const response = await fetch('/internal/admin/api/passkeys', { method: 'DELETE', headers: adminJsonHeaders(), body: JSON.stringify({ tenant_id: tenant.tenantId, user_sub: user.sub }) });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error_description || 'Unable to reset passkeys');
        setUserAuthStatus(tenant, user, { passkey: false });
        state.status = { type: 'ok', message: payload.deleted ? 'Passkeys reset.' : 'No passkeys existed.' };
      } catch (error) {
        state.status = { type: 'error', message: error.message };
      }
      render();
    };
    // Toggles whether the selected user is shared into a target tenant.
    const setUserShare = (targetTenant, checked) => {
      const tenant = selectedTenant(); const user = selectedUser();
      if (!tenant || !user || !targetTenant) return;
      targetTenant.sharedUsers = (targetTenant.sharedUsers || []).filter((entry) => !(entry.tenantId === tenant.tenantId && entry.userSub === user.sub));
      if (checked) targetTenant.sharedUsers.push({ tenantId: tenant.tenantId, userSub: user.sub });
      render();
    };
    // Parses the source tenant/user selected in the shared-account dropdown.
    const selectedShareReference = () => {
      const [tenantId, ...userSubParts] = String(state.selectedShareUserKey || '').split(':');
      const userSub = userSubParts.join(':');
      return tenantId && userSub ? { tenantId, userSub } : undefined;
    };
    // Toggles the selected source user as shared into the current tenant.
    const setSelectedShare = (checked) => {
      const reference = selectedShareReference(); const tenant = selectedTenant();
      if (!tenant || !reference) return;
      tenant.sharedUsers = (tenant.sharedUsers || []).filter((entry) => !(entry.tenantId === reference.tenantId && entry.userSub === reference.userSub));
      if (checked) tenant.sharedUsers.push(reference);
      render();
    };
    // Updates runtime auth status after reset actions without waiting for a full reload.
    const setUserAuthStatus = (tenant, user, patch) => {
      state.authStatus[tenant.tenantId] = state.authStatus[tenant.tenantId] || {};
      state.authStatus[tenant.tenantId][user.sub] = { ...userAuthStatus(tenant, user), ...patch };
    };
    // Adds JSON and CSRF headers required by admin mutation endpoints.
    const adminJsonHeaders = () => ({ 'content-type': 'application/json', 'x-csrf-token': state.csrfToken });
    setTheme(state.themeMode);
    load();
  </script>
</body>
</html>`;
}

/**
 * Renders setup guidance when the internal admin tenant is missing or invalid.
 */
export function renderAdminSetupPage(message: string, example: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OIDC Admin Setup</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #101319; color: #eef4fb; }
    body { margin: 0; min-height: 100dvh; display: grid; place-items: center; padding: 20px; }
    main { width: min(900px, 100%); border: 1px solid #344156; border-radius: 8px; background: #171d26; padding: 18px; display: grid; gap: 14px; }
    h1 { margin: 0; font-size: 22px; }
    p { margin: 0; color: #a9b6c8; }
    pre { margin: 0; padding: 14px; border-radius: 8px; border: 1px solid #344156; background: #0d1118; overflow: auto; color: #d8e2f0; }
  </style>
</head>
<body>
  <main>
    <h1>Admin UI is not configured</h1>
    <p>${escapeHtml(message)}</p>
    <p>Add an internal tenant like this to your config and set its password through the password endpoint.</p>
    <pre>${escapeHtml(example)}</pre>
  </main>
</body>
</html>`;
}

/**
 * Escapes dynamic text before placing it in server-rendered admin HTML.
 */
function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
