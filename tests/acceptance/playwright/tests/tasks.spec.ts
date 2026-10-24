import { test, expect } from '@playwright/test';
import {
  AMBIGUOUS_TASK,
  ARTIFACT_ENABLED,
  ARTIFACT_TASK,
  PERMISSION_TASK,
} from '../support/fixtures';

/**
 * Task list + submit + inspect + cancel — the B11 flow's durable
 * subset, driven through the real SSR forms.
 */
test.describe('task list and lifecycle', () => {
  test('lists the seeded fixtures', async ({ page }) => {
    await page.goto('/app/tasks');
    await expect(page.locator('h1')).toHaveText('Tasks');
    await expect(
      page.getByRole('link', { name: AMBIGUOUS_TASK.title }),
    ).toBeVisible();
    await expect(
      page.getByRole('link', { name: PERMISSION_TASK.title }),
    ).toBeVisible();
    if (ARTIFACT_ENABLED) {
      await expect(
        page.getByRole('link', { name: ARTIFACT_TASK.title }),
      ).toBeVisible();
    }
    // The seeded pending approval surfaces the workspace-wide banner.
    await expect(page.locator('#harness-permission-banner')).toBeVisible();
  });

  test('submit lands on detail; cancel settles the queued task', async ({
    page,
  }) => {
    await page.goto('/app/tasks');

    const title = `R3 acceptance submit ${Date.now()}`;
    await page.getByLabel('Title').fill(title);
    await page
      .locator('select[name="workspace_root_id"]')
      .selectOption({ index: 0 });
    await page.getByLabel('Instruction').fill('acceptance smoke');
    await page.getByRole('button', { name: 'Submit' }).click();

    await page.waitForURL('**/app/tasks/detail?id=*');
    await expect(page.locator('h1')).toHaveText(title);
    await expect(page.locator('main')).toContainText('Status: Queued');

    // Cancel through the rendered PRG form.
    await page.getByRole('button', { name: 'Cancel' }).click();
    await page.waitForURL('**/app/tasks/detail?id=*');
    await expect(page.locator('main')).toContainText(
      /Status: (Settling|Unsuccessful)/,
    );
  });
});
