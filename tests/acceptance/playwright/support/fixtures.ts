/**
 * Shared fixture identities — mirror `tests/acceptance/seed.sql`
 * verbatim; the two files must change together.
 */
export const BOOTSTRAP_TOKEN =
  process.env.CENTRAL_ACCEPTANCE_BOOTSTRAP_TOKEN ??
  'r3-acceptance-bootstrap-token';

export const SENTINEL_WORKSPACE = '019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a';

/** Task waiting on reconciliation with an `ambiguous` harness attempt. */
export const AMBIGUOUS_TASK = {
  id: '019e0000-0000-7000-8000-00000000a001',
  title: 'R3 ambiguous harness attempt',
};

/** Running task with a pending durable approval (bridge absent). */
export const PERMISSION_TASK = {
  id: '019e0000-0000-7000-8000-00000000b001',
  title: 'R3 pending permission request',
  approvalId: '019e0000-0000-7000-8000-00000000b005',
  inputMac: '5a'.repeat(32),
};

/** Completed task carrying the ready `harness.report` artifact. */
export const ARTIFACT_TASK = {
  id: '019e0000-0000-7000-8000-00000000c001',
  title: 'R3 completed task with report artifact',
};

/** Set by the runner once the object store leg is provisioned. */
export const ARTIFACT_ENABLED =
  process.env.CENTRAL_ACCEPTANCE_ARTIFACT === '1';

/** Cookie names owned by the session surface. */
export const COOKIES = {
  session: 'central_session',
  sessionCsrf: 'central_session_csrf',
  preauthCsrf: 'central_preauth_csrf',
} as const;
