import { test as setup, expect } from '@playwright/test';
import { STORAGE_STATE } from '../playwright.config';
import { BOOTSTRAP_TOKEN, COOKIES } from '../support/fixtures';

/**
 * The one-shot bootstrap exchange — doubles as the session provider for
 * every other spec (the token is single-use, so this project runs first
 * and persists `storageState`).
 *
 * Covers: /app/bootstrap render, the `central_preauth_csrf` cookie,
 * pre-auth CSRF enforcement on POST /api/v1/session/bootstrap, the
 * successful exchange's 303 → /app/tasks, and delivery of the
 * `central_session` (HttpOnly) + `central_session_csrf` cookies.
 */
setup('bootstrap exchange delivers the session cookies', async ({
  page,
  baseURL,
}) => {
  await page.goto('/app/tasks');

  // Unauthenticated /app/tasks renders the bootstrap surface.
  await expect(page.locator('h1')).toHaveText('Central Bootstrap');
  const token = page.locator('#bootstrap-token');
  await expect(token).toBeVisible();

  // The pre-auth CSRF pair arrived with the render.
  const cookies = await page.context().cookies();
  const preauth = cookies.find((c) => c.name === COOKIES.preauthCsrf);
  expect(preauth, 'central_preauth_csrf cookie').toBeTruthy();
  expect(preauth?.httpOnly).toBe(true);
  const csrfField = await page.locator('input[name="csrf"]').inputValue();
  expect(csrfField).toBe(preauth?.value);

  // Negative exchanges — rejected before any token verification.
  // `page.request` shares the context's cookie jar, so the
  // `central_preauth_csrf` cookie rides along; only headers/body differ.
  const noOrigin = await page.request.post('/api/v1/session/bootstrap', {
    maxRedirects: 0,
    form: { csrf: csrfField, bootstrap_token: BOOTSTRAP_TOKEN },
  });
  expect(noOrigin.status(), 'missing Origin must be refused').toBe(403);

  const noHeader = await page.request.post('/api/v1/session/bootstrap', {
    maxRedirects: 0,
    headers: { Origin: baseURL! },
    form: { csrf: csrfField, bootstrap_token: BOOTSTRAP_TOKEN },
  });
  expect(
    noHeader.status(),
    'missing X-Central-Preauth-CSRF must be refused',
  ).toBeGreaterThanOrEqual(400);
  expect(noHeader.status()).toBeLessThan(500);

  const queryToken = await page.request.post(
    `/api/v1/session/bootstrap?bootstrap_token=${BOOTSTRAP_TOKEN}`,
    {
      maxRedirects: 0,
      headers: {
        Origin: baseURL!,
        'X-Central-Preauth-CSRF': csrfField,
      },
      form: { csrf: csrfField },
    },
  );
  expect(
    queryToken.status(),
    'query-string tokens are never accepted',
  ).toBeGreaterThanOrEqual(400);
  expect(queryToken.status()).toBeLessThan(500);

  // The real exchange, keyboard-first like upstream B11: focus, type,
  // Enter. bootstrap.js posts with the header and follows the 303.
  await token.click();
  await page.keyboard.type(BOOTSTRAP_TOKEN);
  await page.keyboard.press('Enter');
  await page.waitForURL('**/app/tasks');
  await expect(page.locator('h1')).toHaveText('Tasks');

  const delivered = await page.context().cookies();
  const session = delivered.find((c) => c.name === COOKIES.session);
  const sessionCsrf = delivered.find((c) => c.name === COOKIES.sessionCsrf);
  expect(session, 'central_session delivered').toBeTruthy();
  expect(session?.httpOnly).toBe(true);
  expect(sessionCsrf, 'central_session_csrf delivered').toBeTruthy();
  expect(sessionCsrf?.value).not.toBe('');

  await page.context().storageState({ path: STORAGE_STATE });
});
