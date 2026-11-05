# Feature requirements: Self-service session host restart from Microsoft Teams (NME)

Work item: NME-52310 · Owner: Priya Example · Target: NME 8.1

## Goal
AVD end users frequently raise tickets for "my desktop is frozen". This feature lets an end user type
`/restart-my-desktop` in a Teams chat with the Nerdio bot. NME identifies the user's currently assigned
personal session host and restarts it, then confirms in Teams.

## User stories
1. As an AVD user, I can ask the Nerdio Teams bot to restart my personal session host so I don't wait for IT.
2. As an IT admin, I can enable or disable the feature per host pool and see every restart in the NME audit log.
3. As an IT admin, I can require the user to confirm before the restart happens.

## Architecture (see architecture.png)
- Users interact with the bot in Microsoft Teams. Azure Bot Service delivers activities to a new HTTPS
  endpoint in the NME App Service: `POST /api/teams/activity`. The Bot Framework JWT in the Authorization
  header is validated (issuer, audience = bot app id).
- The endpoint resolves the Teams user's Entra object id from the activity, looks up the user's assigned
  personal host in the NME SQL database (table `HostAssignments`), and enqueues a restart job.
- The restart worker uses the NME managed identity (Virtual Machine Contributor on the host pool resource
  group) to call ARM `POST .../virtualMachines/{vm}/restart`.
- A confirmation card is sent back to the user via the Bot Framework REST API.
- Every request and restart is written to the NME audit log (Log Analytics).

## Data
- Teams activity payload: user display name, Entra object id, tenant id, message text.
- Host assignment: user id -> VM resource id (existing data).
- No new data is persisted apart from the audit log entry (user id, VM, result, timestamp).

## Non-functional
- Restart must be rate limited: at most one restart per user per 10 minutes.
- Feature is off by default per host pool.
- Only personal (1:1) hosts are eligible; pooled hosts are never restarted.
