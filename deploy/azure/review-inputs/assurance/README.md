# Disposable Azure assurance inputs

These inputs bind case `CASE-323731951859164421` in tenant `ASSURANCE-LAB` to
the empty, tagged storage account `elcapassure8f51fb20985d`. The account exists
only to exercise the complete El Capitan review, approval, deployment,
monitoring, verification, and rollback lifecycle.

The source snapshot and imported Terraform state contain no credentials or
data-plane content. The service context records the empty container inventory,
zero-dependency topology, exact-resource executor scope, and explicit 24x7 lab
window policy. Eiger is not referenced or modified by this run.
