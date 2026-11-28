# Isolation and containment verification

Run only in a selected disposable environment. Observe sibling isolation over
TCP and ICMP, the Incus and SSH host boundaries, authorized service
reachability, resource pressure containment, and the absence of host devices
inside guests. Verify the relevant health checks after each fault exercise.

A routed firewall rule alone cannot establish isolation between guests on the
same bridge. Test the actual layer-two path and the selected port isolation
setting. Record the real topology, commands, and observed results in the
authorized operations register.
