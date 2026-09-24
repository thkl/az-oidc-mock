export function renderAdminPage(user) {
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
  <script src="https://unpkg.com/vue@3/dist/vue.global.prod.js"></script>
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
    .row-list { display: grid; gap: 6px; align-content: start; }
    .row-button { min-height: 0; display: grid; gap: 3px; text-align: left; padding: 8px; }
    .row-button strong { font-weight: 440; }
    .row-button[aria-current="true"] { border-color: rgba(37, 99, 235, .42); background: var(--primary-soft); }
    .row-button small { color: var(--muted); overflow-wrap: anywhere; }
    .checks { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
    .check { display: inline-flex; gap: 7px; align-items: center; color: var(--text); font-size: 12px; font-weight: 360; }
    .check input { width: 16px; min-height: 16px; }
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
                <label>Client Secret <input v-model="selectedClient.clientSecret" autocomplete="new-password"></label>
              </div>
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
              <div class="actions"><button class="danger" type="button" @click="removeUser">Delete User</button></div>
            </div>
            <div v-else class="empty">Select or add a user.</div>
          </div>
        </section>
      </template>
    </main>
  </div>

  <script>
    const { createApp } = Vue;
    const blankTenant = () => ({
      tenantId: 'tenant-' + Math.random().toString(36).slice(2, 7),
      displayName: 'New Tenant',
      clients: [],
      users: [],
      devices: [],
      secure: false,
      enableSessions: true,
      sessionLifetimeSeconds: 28800
    });
    const splitLines = (value) => String(value || '').split(/\\r?\\n|,/).map((item) => item.trim()).filter(Boolean);
    const splitTokens = (value) => String(value || '').split(/[\\s,]+/).map((item) => item.trim()).filter(Boolean);
    const clone = (value) => JSON.parse(JSON.stringify(value));
    const decorate = (config) => {
      const copy = clone(config);
      for (const tenant of copy.tenants) {
        tenant.devicesText = JSON.stringify(tenant.devices || [], null, 2);
        for (const client of tenant.clients) {
          client.redirectUrisText = (client.redirectUris || []).join('\\n');
          client.allowedScopesText = (client.allowedScopes || []).join(' ');
        }
        for (const user of tenant.users) {
          user.rolesText = (user.roles || []).join('\\n');
          user.claimsText = JSON.stringify(user.claims || {}, null, 2);
        }
      }
      return copy;
    };
    const clean = (config) => {
      const copy = clone(config);
      for (const tenant of copy.tenants) {
        tenant.devices = JSON.parse(tenant.devicesText || '[]');
        delete tenant.devicesText;
        for (const client of tenant.clients) {
          client.redirectUris = splitLines(client.redirectUrisText);
          client.allowedScopes = splitTokens(client.allowedScopesText);
          if (!client.clientSecret) delete client.clientSecret;
          delete client.redirectUrisText;
          delete client.allowedScopesText;
        }
        for (const user of tenant.users) {
          user.roles = splitLines(user.rolesText);
          user.claims = JSON.parse(user.claimsText || '{}');
          delete user.rolesText;
          delete user.claimsText;
        }
      }
      return copy;
    };

    createApp({
      data() {
        return {
          loading: true,
          saving: false,
          editable: { tenants: [] },
          selectedTenantId: '',
          selectedClientIndex: 0,
          selectedUserIndex: 0,
          themeMode: localStorage.getItem('az_oidc_admin_theme') || 'system',
          status: { type: '', message: '' }
        };
      },
      computed: {
        selectedTenant() { return this.editable.tenants.find((tenant) => tenant.tenantId === this.selectedTenantId) || this.editable.tenants[0]; },
        selectedClient() { return this.selectedTenant?.clients[this.selectedClientIndex]; },
        selectedUser() { return this.selectedTenant?.users[this.selectedUserIndex]; },
        totalClients() { return this.editable.tenants.reduce((sum, tenant) => sum + tenant.clients.length, 0); },
        totalUsers() { return this.editable.tenants.reduce((sum, tenant) => sum + tenant.users.length, 0); }
      },
      async mounted() {
        this.applyTheme();
        await this.load();
      },
      methods: {
        applyTheme() {
          if (this.themeMode === 'light' || this.themeMode === 'dark') {
            document.documentElement.dataset.theme = this.themeMode;
          } else {
            delete document.documentElement.dataset.theme;
          }
        },
        setTheme(theme) {
          this.themeMode = theme;
          if (theme === 'system') {
            localStorage.removeItem('az_oidc_admin_theme');
          } else {
            localStorage.setItem('az_oidc_admin_theme', theme);
          }
          this.applyTheme();
        },
        async load() {
          this.loading = true;
          this.status = { type: '', message: '' };
          try {
            const response = await fetch('/internal/admin/api/config');
            if (!response.ok) throw new Error((await response.json()).error_description || 'Unable to load config');
            const payload = await response.json();
            this.editable = decorate(payload.config);
            this.selectedTenantId = this.editable.tenants[0]?.tenantId || '';
            this.selectedClientIndex = 0;
            this.selectedUserIndex = 0;
          } catch (error) {
            this.status = { type: 'error', message: error.message };
          } finally {
            this.loading = false;
          }
        },
        async save() {
          this.saving = true;
          this.status = { type: '', message: '' };
          try {
            const response = await fetch('/internal/admin/api/config', {
              method: 'PUT',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ config: clean(this.editable) })
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error_description || 'Unable to save config');
            this.editable = decorate(payload.config);
            this.status = { type: 'ok', message: 'Configuration saved.' };
          } catch (error) {
            this.status = { type: 'error', message: error.message };
          } finally {
            this.saving = false;
          }
        },
        selectTenant(tenantId) {
          this.selectedTenantId = tenantId;
          this.selectedClientIndex = 0;
          this.selectedUserIndex = 0;
        },
        addTenant() {
          const tenant = decorate({ tenants: [blankTenant()] }).tenants[0];
          tenant.clients.push({ clientId: 'new-client', redirectUris: [], redirectUrisText: '', allowedScopes: ['openid', 'profile', 'email'], allowedScopesText: 'openid profile email', enabled: true });
          tenant.users.push({ sub: 'new-user', name: 'New User', email: 'user@example.test', preferred_username: 'user@example.test', roles: [], rolesText: '', claims: {}, claimsText: '{}' });
          this.editable.tenants.push(tenant);
          this.selectTenant(tenant.tenantId);
        },
        duplicateTenant() {
          const tenant = clone(this.selectedTenant);
          tenant.tenantId = tenant.tenantId + '-copy';
          tenant.displayName = tenant.displayName + ' Copy';
          this.editable.tenants.push(tenant);
          this.selectTenant(tenant.tenantId);
        },
        removeTenant() {
          if (!confirm('Delete this tenant from the config?')) return;
          this.editable.tenants = this.editable.tenants.filter((tenant) => tenant !== this.selectedTenant);
          this.selectTenant(this.editable.tenants[0]?.tenantId || '');
        },
        addClient() {
          this.selectedTenant.clients.push({ clientId: 'new-client', clientSecret: '', redirectUris: [], redirectUrisText: '', allowedScopes: ['openid', 'profile', 'email'], allowedScopesText: 'openid profile email', enabled: true });
          this.selectedClientIndex = this.selectedTenant.clients.length - 1;
        },
        removeClient() {
          if (!confirm('Delete this client?')) return;
          this.selectedTenant.clients.splice(this.selectedClientIndex, 1);
          this.selectedClientIndex = Math.max(0, this.selectedClientIndex - 1);
        },
        addUser() {
          this.selectedTenant.users.push({ sub: 'new-user', name: 'New User', email: 'user@example.test', preferred_username: 'user@example.test', roles: [], rolesText: '', claims: {}, claimsText: '{}' });
          this.selectedUserIndex = this.selectedTenant.users.length - 1;
        },
        removeUser() {
          if (!confirm('Delete this user?')) return;
          this.selectedTenant.users.splice(this.selectedUserIndex, 1);
          this.selectedUserIndex = Math.max(0, this.selectedUserIndex - 1);
        }
      }
    }).mount('#app');
  </script>
</body>
</html>`;
}
export function renderAdminSetupPage(message, example) {
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
function escapeHtml(value) {
    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
}
