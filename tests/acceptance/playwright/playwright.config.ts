import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

/**
 * Phase R3 acceptance — server-rendered Web UI against a live
 * `central serve` (`scripts/r3-acceptance.sh` wires DATABASE + seed +
 * env). `CENTRAL_ACCEPTANCE_BASE_URL` points at the app listener.
 *
 * The `setup` project performs the one-shot bootstrap exchange and
 * persists the authenticated storage state every other project reuses —
 * the generation-0 bootstrap token is single-use by design.
 */
export const STORAGE_STATE = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '.auth',
  'session.json',
);

export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.CENTRAL_ACCEPTANCE_BASE_URL ?? 'http://127.0.0.1:8080',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'setup', testMatch: /bootstrap\.setup\.ts/ },
    {
      name: 'chromium',
      dependencies: ['setup'],
      use: { ...devices['Desktop Chrome'], storageState: STORAGE_STATE },
    },
  ],
});
