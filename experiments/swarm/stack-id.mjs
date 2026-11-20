/**
 * GCP swarm stack labels, as minted by cloud/gcp/swarm-engage.sh on the VM:
 * `gcp:<sanitised hostname, 1-48 chars>:<8 hex>`. A GCP test must expect one;
 * a missing, `unlabelled` or local label fails closed.
 */
export const GCP_STACK_ID_RE = /^gcp:[A-Za-z0-9_.-]{1,48}:[a-f0-9]{8}$/;
export const isGcpStackId = (id) => typeof id === 'string' && GCP_STACK_ID_RE.test(id);
export function requireGcpStackId(id, where = 'stack id') {
  if (!isGcpStackId(id)) {
    throw new Error(`${where} ${id ? `"${id}" is not a GCP swarm stack id (gcp:<host>:<8 hex>)` : 'is missing'}: the VM may run an older swarm-engage.sh; re-run lab.sh swarm before testing`);
  }
  return id;
}

/**
 * Operator-managed VMs reached over plain SSH label their stacks `ssh:<host>:<8 hex>`
 * (swarm-engage.sh with GATRA_STACK_PREFIX=ssh), so evidence never calls them GCP.
 */
export const SSH_STACK_ID_RE = /^ssh:[A-Za-z0-9_.-]{1,48}:[a-f0-9]{8}$/;
export function requireLabStackId(id, target = 'gcp', where = 'stack id') {
  if (target !== 'ssh') return requireGcpStackId(id, where);
  if (typeof id !== 'string' || !SSH_STACK_ID_RE.test(id)) {
    throw new Error(`${where} ${id ? `"${id}" is not an SSH swarm stack id (ssh:<host>:<8 hex>)` : 'is missing'}: restart the stack from the dashboard before testing`);
  }
  return id;
}
