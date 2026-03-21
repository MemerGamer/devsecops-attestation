# deny-reasons-string policy: deny_reasons is a scalar string, not a set.
# Used to test the non-map deny_reasons branch in Evaluate.
package devsecops.gate

default allow := false

deny_reasons := "not-a-set"
