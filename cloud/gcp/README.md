# Temporary GCP deception lab

Start with the [GCP live demo guide](../../docs/GCP-LIVE-DEMO.md) for an explained
walkthrough of the deployed demo and the operator's observed results.

This deploys actual container services to one Compute Engine VM. The test sends
real HTTP traffic and displays the resulting service logs. Records and credentials
are synthetic. The driver is deterministic, not an AI model. OpenCanary detection
and the V1 mock API's containment are separate paths. The separate V2 validator
connects trusted OpenCanary alerts to peer-specific application denial.

The deployment requires an explicitly chosen project with billing and permissions
to enable APIs, create Compute Engine/network resources, and connect with OS Login
and IAP. It never changes the active gcloud project or grants IAM roles.

## Review and deploy

From `deception-lab/`:

```bash
# Optional: select an already-authenticated account without changing defaults.
export GATRA_GCP_ACCOUNT=your-google-account@example.com
bash cloud/gcp/lab.sh plan YOUR_PROJECT_ID
bash cloud/gcp/lab.sh deploy YOUR_PROJECT_ID
```

Default location: Jakarta, `asia-southeast2-a`. Optional third and fourth arguments
select the zone and resource name. Use a sandbox project where possible.

The plan creates an `e2-small` Ubuntu 24.04 VM with a 20 GB standard boot disk,
a dedicated VPC/subnet, and an IAP-only SSH ingress rule. No HTTP ports are public.
The VM has no service account or OAuth scopes. An ephemeral external IP allows
package/image downloads on the host; decoy services stay on Docker's internal
network with no published ports. The bundle contains only lab code/configuration
and the demo script; local credentials and model weights are not uploaded.

Compute Engine automatically stops the VM after one hour. That is a runtime limit,
not a monetary budget. The disk remains billable until deletion. VM, disk, IPv4,
and transfer charges follow your project's regional pricing; this is not a free
tier deployment. No GPU or cloud model API is used.

## What you will see

1. **None:** the scripted agent discovers the synthetic service key and retrieves
   the records export.
2. **Static:** the agent follows a backup-file decoy; using its canary credential
   terminates the mock API session.
3. **Adaptive:** additional decoy pages keep the agent engaged until the mock API
   terminates its session after sustained engagement.
4. **OpenCanary:** an actual HTTP GET and POST login generate `http.get` and
   `http.login-attempt` events. The adapter redacts credentials and the collector
   receives the events. The script checks that the login event reached the
   collector and that the submitted password did not appear in telemetry.

Repeat the demo or inspect logs:

```bash
bash cloud/gcp/lab.sh demo YOUR_PROJECT_ID
bash cloud/gcp/lab.sh logs YOUR_PROJECT_ID
```

To watch logs continuously:

```bash
gcloud compute ssh gatra-deception-demo --project=YOUR_PROJECT_ID \
  --zone=asia-southeast2-a --tunnel-through-iap \
  --command='sudo docker compose -p gatra-cloud-demo -f /opt/deception-lab/lab/compose.yaml --profile opencanary logs -f collector canary-adapter honeypot'
```

## Validate Defense V2

Fresh deployments include the separate V2 stack and validator. Run:

```bash
bash cloud/gcp/lab.sh validate-defense YOUR_PROJECT_ID
```

This uses the existing VM, generates fresh synthetic control/service keys, checks
14 scenarios including actual OpenCanary-triggered denial of a valid stolen lab
token, and checks 100 legitimate requests from another client. It prints evidence
and removes the V2 containers/network afterward. V1 remains separate. This does
not run an AI model. See the [validated defense report](../../docs/VALIDATED-DEFENSE.md)
for the completed cloud evidence, separate 60-session local-model study and scope.

## Swarm engagements (live red team vs. deception)

`swarm` uploads the swarm stack (defense gateway with per-agent signed peer
identities, OpenCanary, collector, and a swarm hub publishing SSE + a bounded
reverse proxy on VM loopback `127.0.0.1:18092`) and starts it. Ephemeral
`LAB_CONTROL_KEY`/`LAB_LEGIT_KEY` are printed once over IAP-encrypted SSH.

```bash
bash cloud/gcp/lab.sh swarm YOUR_PROJECT_ID            # start; prints keys + tunnel command
bash cloud/gcp/lab.sh swarm-logs YOUR_PROJECT_ID       # defense/hub/collector logs
bash cloud/gcp/lab.sh swarm-stop YOUR_PROJECT_ID       # remove swarm stack and keys
```

Then on your machine: open the printed IAP tunnel, run
`npm run deception-lab:swarm -- --provider ollama --model qwen3.5:4b-q8_0 …`
and watch the dashboard **Live** tab. The V1 demo and defense validation
stacks are untouched. See [docs/SWARM-LAB.md](../../docs/SWARM-LAB.md).

## Cleanup

Copy needed logs before deleting the VM. Cleanup deletes the named lab VM and its
auto-deleted boot disk, firewall rule, subnet, and VPC. It leaves APIs enabled and
does not touch other project resources.

```bash
bash cloud/gcp/lab.sh cleanup YOUR_PROJECT_ID
```

If deployment stops partway through, inspect the printed error and remove any
already-created named resources. The cleanup sequence stops on errors, so if the
VM was never created, remove the named firewall/subnet/network individually.

References: [IAP access](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding),
[VM runtime limits](https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime),
[charges after stopping](https://docs.cloud.google.com/compute/docs/instances/stop-start-instance),
[Compute pricing](https://cloud.google.com/products/compute/pricing/general-purpose).
