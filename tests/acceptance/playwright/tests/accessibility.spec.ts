import { test, expect, type Page } from '@playwright/test';
import { AMBIGUOUS_TASK, PERMISSION_TASK } from '../support/fixtures';

/**
 * Accessibility smoke — semantic assertions on the SSR surface
 * (landmarks, document language/title, label association, live
 * regions). When `@axe-core/playwright` is installed the same pages get
 * an axe pass that must be free of serious/critical violations.
 */

async function semanticSmoke(page: Page, url: string) {
  await page.goto(url);
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page).toHaveTitle(/\S/);
  await expect(page.locator('main')).toBeVisible();
  await expect(page.locator('h1')).toBeVisible();
}

async function axeSmoke(page: Page) {
  const mod = await import('@axe-core/playwright').catch(() => null);
  if (!mod) {
    return;
  }
  const results = await new mod.AxeBuilder({ page }).include('main').analyze();
  const serious = results.violations.filter(
    (v) => v.impact === 'critical' || v.impact === 'serious',
  );
  expect(
    serious,
    `axe serious/critical violations: ${JSON.stringify(serious.map((v) => v.id))}`,
  ).toEqual([]);
}

test.describe('accessibility smoke', () => {
  test('bootstrap page: landmarks, labels, required markers', async ({
    page,
  }) => {
    // A fresh context has no session — /app/tasks renders bootstrap.
    await page.context().clearCookies();
    await semanticSmoke(page, '/app/tasks');
    await expect(page.locator('nav')).toHaveCount(0); // no nav on bootstrap
    const token = page.locator('#bootstrap-token');
    await expect(token).toHaveAttribute('aria-required', 'true');
    await expect(page.locator('label[for="bootstrap-token"]')).toBeVisible();
    await expect(page.locator('fieldset > legend')).toContainText(
      'Bootstrap credentials',
    );
    await expect(page.locator('#form-error')).toHaveAttribute(
      'role',
      'alert',
    );
    await axeSmoke(page);
  });

  test('task list: landmarks + labelled submit controls', async ({
    page,
  }) => {
    await semanticSmoke(page, '/app/tasks');
    await expect(page.locator('nav')).toBeVisible();
    await expect(page.getByLabel('Title')).toBeEditable();
    await expect(page.getByLabel('Repository root')).toBeEditable();
    await expect(page.getByLabel('Instruction')).toBeEditable();
    await expect(page.locator('ul[aria-live="polite"]')).toBeVisible();
    await axeSmoke(page);
  });

  test('task detail: landmarks + alert/status regions', async ({ page }) => {
    await semanticSmoke(
      page,
      `/app/tasks/detail?id=${PERMISSION_TASK.id}`,
    );
    await expect(
      page.locator('#harness-permission-pending[aria-labelledby="permission-h"]'),
    ).toBeVisible();
    await expect(page.locator('#harness-permission-banner')).toHaveAttribute(
      'role',
      'alert',
    );
    await axeSmoke(page);

    await page.goto(`/app/tasks/detail?id=${AMBIGUOUS_TASK.id}`);
    await expect(
      page.locator('#harness-resolve[aria-labelledby="harness-resolve-h"]'),
    ).toBeVisible();
  });
});
