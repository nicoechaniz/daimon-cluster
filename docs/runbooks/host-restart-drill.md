# Host restart verification

Read the authorized operations register before planning a drill. Use only a
currently approved receiver and maintenance window. Preserve explicit holds,
active work, and a verified recovery route.

Before restarting an approved receiver, record the boot ID, selected service
definitions, receiver health, and audit and reconciliation baselines. After
SSH returns, compare the boot IDs and verify the following through the current
receiving tools:

- Required services and guests started, and their real health checks pass.
- Network isolation, firewall, and private bind scope match the baseline.
- The scheduled service recovery path works without a manual second restart.
- Audit and reconciliation state remains consistent.
- The selected Matrix reader authenticates against the expected receiver.

Retain results and configuration details in the authorized operations register.
Historical drills confer no authority to reboot a current host.
