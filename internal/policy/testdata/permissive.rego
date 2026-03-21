# Permissive test policy: always allows deployment.
# Used in integration tests to test the gate mechanism independently of business rules.
package devsecops.gate

default allow := true
