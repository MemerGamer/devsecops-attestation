# Deny-all test policy: blocks all deployments.
# Used to test that custom policy files are loaded and respected.
package devsecops.gate

import future.keywords.if

default allow := false

deny_reasons[msg] if {
    true
    msg := "deny-all policy active"
}
