import type { MockUser } from "../config.js";

export function renderAdminPage(user: MockUser): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OIDC Admin</title>
  <script src="https://unpkg.com/vue@3/dist/vue.global.prod.js"></script>
  <style>
    :root {
      color-scheme: dark;
      --bg: #101319;
      --surface: #171d26;
      --surface-2: #202836;
      --line: #344156;
      --text: #eef4fb;
      --muted: #a9b6c8;
      --primary: #2dd4bf;
      --primary-dark: #0f766e;
      --danger: #fb7185;
      --warning: #fbbf24;
      --focus: #f8fafc;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100dvh; background: var(--bg); color: var(--text); }
    button, input, textarea, select { font: inherit; }
    button { min-height: 40px; border: 1px solid var(--line); border-radius: 6px; background: var(--surface-2); color: var(--text); padding: 8px 12px; cursor: pointer; }
    button:hover { border-color: var(--primary); }
    button:focus-visible, input:focus-visible, textarea:focus-visible, select:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
    button.primary { background: var(--primary); border-color: var(--primary); color: #042f2e; font-weight: 700; }
    button.danger { border-color: color-mix(in srgb, var(--danger), white 12%); color: #fecdd3; }
    button[disabled] { opacity: .55; cursor: not-allowed; }
    input, textarea, select { width: 100%; min-height: 40px; border: 1px solid var(--line); border-radius: 6px; background: #0d1118; color: var(--text); padding: 8px 10px; }
    textarea { min-height: 86px; resize: vertical; font-family: "Fira Code", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; line-height: 1.5; }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 13px; font-weight: 650; }
    .shell { min-height: 100dvh; display: grid; grid-template-columns: minmax(240px, 300px) 1fr; }
    aside { border-right: 1px solid var(--line); background: #0d1118; padding: 18px; display: grid; align-content: start; gap: 16px; }
    main { min-width: 0; padding: 18px; display: grid; gap: 16px; align-content: start; }
    .brand { display: grid; gap: 4px; }
    .brand h1 { margin: 0; font-size: 18px; line-height: 1.2; }
    .brand p, .meta { margin: 0; color: var(--muted); font-size: 13px; }
    .toolbar { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface); padding: 12px; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .tenant-list { display: grid; gap: 8px; }
    .tenant-tab { width: 100%; display: grid; gap: 4px; text-align: left; padding: 10px; }
    .tenant-tab[aria-current="true"] { border-color: var(--primary); background: #12312f; }
    .tenant-tab span { font-weight: 700; }
    .tenant-tab small { color: var(--muted); overflow-wrap: anywhere; }
    .panel { border: 1px solid var(--line); border-radius: 8px; background: var(--surface); }
    .panel-header { padding: 12px 14px; border-bottom: 1px solid var(--line); display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .panel-header h2 { margin: 0; font-size: 16px; }
    .panel-body { padding: 14px; display: grid; gap: 14px; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .triple { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
    .split { display: grid; grid-template-columns: minmax(220px, 320px) 1fr; gap: 14px; }
    .row-list { display: grid; gap: 8px; align-content: start; }
    .row-button { display: grid; gap: 4px; text-align: left; padding: 10px; }
    .row-button[aria-current="true"] { border-color: var(--primary); background: #12312f; }
    .row-button small { color: var(--muted); overflow-wrap: anywhere; }
    .checks { display: flex; flex-wrap: wrap; gap: 14px; align-items: center; }
    .check { display: inline-flex; gap: 8px; align-items: center; color: var(--text); font-size: 14px; }
    .check input { width: 18px; min-height: 18px; }
    .status { border-radius: 6px; padding: 9px 11px; font-size: 13px; border: 1px solid var(--line); color: var(--muted); }
    .status.ok { border-color: #166534; color: #bbf7d0; background: #052e1a; }
    .status.error { border-color: #9f1239; color: #fecdd3; background: #3b0713; }
    .empty { color: var(--muted); border: 1px dashed var(--line); border-radius: 8px; padding: 16px; }
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
          client.allowedScopes = splitLines(client.allowedScopesText);
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
      async mounted() { await this.load(); },
      methods: {
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

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
