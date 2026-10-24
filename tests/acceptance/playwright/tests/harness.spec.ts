import { test, expect } from '@playwright/test';
import {
  AMBIGUOUS_TASK,
  COOKIES,
  PERMISSION_TASK,
} from '../support/fixtures';

/**
 * Harness attempt detail + permission PRG surface.
 *
 * The R3 dev slice runs without a live harness backend, so the
 * orchestrator's in-memory approval bridge holds nothing: the pending
 * durable approval renders the panel's waiting copy and every decision
 * POST answers through the stale-decision path — `303` back to detail
 * with `?permission=stale` and the "no longer pending" banner. The
 * Allow and Deny decisions exercise the identical route, prelude, and
 * PRG surface.
 */

async function sessionCsrf(page: import('@playwright/test').Page) {
  const cookies = await page.context().cookies();
  const csrf = cookies.find((c) => c.name === COOKIES.sessionCsrf);
  expect(csrf, 'session csrf cookie').toBeTruthy();
  return csrf!.value;
}

test.describe('harness attempt detail and permission PRG', () => {
  test('pending permission renders banner + panel; allow/deny answer stale', async ({
    page,
    baseURL,
  }) => {
    await page.goto('/app/tasks');

    // The banner carries the operator to the pending request's task.
    const banner = page.locator('#harness-permission-banner');
    await expect(banner).toBeVisible();
    await banner.getByRole('link').click();
    await page.waitForURL(`**/app/tasks/detail?id=${PERMISSION_TASK.id}`);
    await expect(page.locator('h1')).toHaveText(PERMISSION_TASK.title);

    // The durable pending approval renders the pending panel; without a
    // live bridge entry the panel explains the request cannot be
    // answered here instead of offering Allow/Deny.
    const panel = page.locator('#harness-permission-pending');
    await expect(panel).toBeVisible();
    await expect(panel.getByRole('status')).toContainText(
      'cannot be answered from here',
    );
    await expect(panel.getByRole('button', { name: 'Allow' })).toHaveCount(0);

    const csrf = await sessionCsrf(page);
    for (const decision of ['allow', 'deny'] as const) {
      const resp = await page.request.post('/app/tasks/harness/permission', {
        maxRedirects: 0,
        headers: { Origin: baseURL! },
        form: {
          csrf,
          task_id: PERMISSION_TASK.id,
          approval_id: PERMISSION_TASK.approvalId,
          input_mac: PERMISSION_TASK.inputMac,
          decision,
        },
      });
      expect(resp.status(), `${decision} must be a 303 PRG`).toBe(303);
      const location = resp.headers()['location'];
      expect(location).toContain(`/app/tasks/detail?id=${PERMISSION_TASK.id}`);
      expect(location).toContain('permission=stale');

      await page.goto(location);
      await expect(page.locator('#permission-notice')).toHaveText(
        'This request is no longer pending.',
      );
    }
  });

  test('ambiguous attempt renders the resolve panel; Mark cancelled settles', async ({
    page,
  }) => {
    await page.goto('/app/tasks');
    await page.getByRole('link', { name: AMBIGUOUS_TASK.title }).click();
    await page.waitForURL(`**/app/tasks/detail?id=${AMBIGUOUS_TASK.id}`);

    await expect(page.locator('main')).toContainText('Status: Waiting');
    const panel = page.locator('#harness-resolve');
    await expect(panel).toBeVisible();
    await expect(panel).toContainText('ambiguous');

    await panel
      .getByRole('button', { name: 'Mark cancelled (operator resolved)' })
      .click();
    await page.waitForURL(`**/app/tasks/detail?id=${AMBIGUOUS_TASK.id}*`);

    // The two durable commits (request cancellation, then the
    // reconciliation resolution) leave the task Settling or
    // Unsuccessful — both are post-resolve terminal vocabulary.
    await expect(page.locator('main')).toContainText(
      /Status: (Settling|Unsuccessful)/,
    );
  });
});
