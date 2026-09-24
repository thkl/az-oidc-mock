/**
 * Renders the login page for an authorization request.
 */
export function renderLoginPage(tenant, params, error) {
    const hiddenFields = Object.entries(params)
        .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
        .join("\n");
    const formContent = tenant.secure ? `
      ${error ? `<div class="error" role="alert">${escapeHtml(error)}</div>` : ""}
      <label>
        <span>Email</span>
        <input name="username" type="email" autocomplete="username" required autofocus>
      </label>
      <label>
        <span>Password</span>
        <input name="password" type="password" autocomplete="current-password" required>
      </label>
      <button class="primary" type="submit">Sign in</button>`
        : tenant.users
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
    label { display: grid; gap: 6px; color: #334155; font-weight: 600; }
    input { width: 100%; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 6px; padding: 11px 12px; font: inherit; }
    input:focus { outline: 2px solid #99c2f2; border-color: #2878d8; }
    .primary { appearance: none; border: 0; border-radius: 6px; background: #2878d8; color: #fff; font: inherit; font-weight: 650; padding: 12px 14px; cursor: pointer; }
    .primary:hover { background: #1f66bd; }
    .error { border: 1px solid #f0b8b8; border-radius: 6px; background: #fff5f5; color: #9b1c1c; padding: 10px 12px; }
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
      <p>${tenant.secure ? "Sign in to continue." : "Select a mock user to continue."}</p>
    </header>
    <form method="post" action="/${encodeURIComponent(tenant.tenantId)}/login">
      ${hiddenFields}
      ${formContent}
    </form>
  </main>
</body>
</html>`;
}
/**
 * Escapes dynamic text before placing it into the login page HTML.
 */
function escapeHtml(value) {
    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
}
