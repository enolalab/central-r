import { test, expect } from '@playwright/test';
import { ARTIFACT_ENABLED, ARTIFACT_TASK } from '../support/fixtures';

/**
 * Artifact delivery — gated on the object-store leg
 * (`CENTRAL_ACCEPTANCE_ARTIFACT=1` from the runner when a MinIO/S3
 * endpoint was reachable and the report body was seeded at the
 * `v1/ready/…` object key the runner prints).
 */
test.describe('artifact preview and download', () => {
  test.skip(!ARTIFACT_ENABLED, 'object store not provisioned');

  test('preview renders the report body; download attaches report.md', async ({
    page,
  }) => {
    await page.goto('/app/tasks');
    await page.getByRole('link', { name: ARTIFACT_TASK.title }).click();
    await page.waitForURL(`**/app/tasks/detail?id=${ARTIFACT_TASK.id}`);

    const preview = page.getByRole('link', { name: 'Preview report' });
    await expect(preview).toBeVisible();
    await preview.click();
    await page.waitForURL('**/app/tasks/artifact/preview?id=*');
    await expect(page.locator('pre')).toContainText('R3 acceptance report');

    await page.goto(`/app/tasks/detail?id=${ARTIFACT_TASK.id}`);
    const download = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Download report' }).click();
    const file = await download;
    expect(file.suggestedFilename()).toBe('report.md');
  });
});
