export function renderLoginPage(tenant, params) {
    const hiddenFields = Object.entries(params)
        .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
        .join("\n");
    const users = tenant.users
        .map((user) => `
        <button class="user" type="submit" name="user_sub" value="${escapeHtml(user.sub)}">
          <span>${escapeHtml(user.name)}</span>
          <small>${escapeHtml(user.preferred_username)}</small>
        </button>`)
        .join("\n");
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(tenant.displayName)} Login</title>
  <style>
    :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f6f8fb; color: #172033; }
    main { width: min(440px, calc(100vw - 32px)); background: #fff; border: 1px solid #d7dde8; border-radius: 8px; box-shadow: 0 14px 40px rgb(20 31 54 / 12%); }
    header { padding: 24px 24px 12px; border-bottom: 1px solid #e7ebf2; }
    h1 { margin: 0; font-size: 22px; font-weight: 650; }
    p { margin: 8px 0 0; color: #526070; }
    form { display: grid; gap: 10px; padding: 18px; }
    .user { appearance: none; width: 100%; border: 1px solid #d9e0ea; border-radius: 8px; background: #fff; text-align: left; padding: 14px 16px; cursor: pointer; }
    .user:hover { border-color: #2878d8; background: #f7fbff; }
    .user span { display: block; font-weight: 650; color: #142033; }
    .user small { display: block; margin-top: 3px; color: #617085; }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>${escapeHtml(tenant.displayName)}</h1>
      <p>Select a mock user to continue.</p>
    </header>
    <form method="post" action="/${encodeURIComponent(tenant.tenantId)}/login">
      ${hiddenFields}
      ${users}
    </form>
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
