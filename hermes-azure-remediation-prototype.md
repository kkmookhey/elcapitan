# Azure Eiger + AWS-Hosted Hermes Remediation Prototype

Yes. **Eiger in Azure; Hermes control plane in AWS.** For this prototype, that is the architecture I would choose.

Why AWS for Hermes? Because it cleanly separates the security platform from the environment it is assessing. If Eiger is compromised, the attacker does not automatically land on the machine holding your agent runtime, findings, GitHub access, and remediation logic. It also makes the eventual managed-service story cleaner: “our platform securely assesses and remediates your cloud,” rather than “we install a privileged AI inside your cloud.”

The first prototype should be extremely specific:

> **Prowler finds a real Azure problem → Hermes validates and prioritizes it → correlates it with Eiger’s GitHub/IaC → proposes the exact remediation → challenges it for production impact → generates a patch/PR + deployment + rollback + verification plan.**

No autonomous deployment yet.

## 1. Build this exact architecture

```text
                       AWS
          ┌──────────────────────────┐
          │ security-agent-lab EC2   │
          │                          │
          │ Hermes                   │
          │ Prowler                  │
          │ Trivy                    │
          │ Azure CLI                │
          │ Git / GitHub CLI         │
          │ Terraform                │
          │ jq / Python              │
          │                          │
          │ Remediation workflow     │
          └────────────┬─────────────┘
                       │
          READ ONLY    │
                       ▼
                  Azure Tenant
          ┌──────────────────────────┐
          │                          │
          │         EIGER            │
          │                          │
          │ App Service / Container  │
          │ Storage                  │
          │ Key Vault                │
          │ Managed Identity         │
          │ VNet                     │
          │ Log Analytics            │
          └──────────────────────────┘
                       ▲
                       │
                       │ maps resources
                       │ to source
                       │
                 GitHub repos
              ┌────────────────┐
              │ Eiger code     │
              │ Terraform/Bicep│
              │ Dockerfile     │
              │ CI/CD          │
              └────────────────┘
```

Prowler officially supports Azure, GitHub and IaC as providers; its IaC provider itself uses Trivy underneath. It can produce JSON-OCSF output, which is ideal as your machine-readable intake format. citeturn977779view3

---

# 2. Create the AWS box

I would use:

```text
Ubuntu 24.04
m7i.xlarge initially
4 vCPU
16 GB RAM
100 GB gp3 encrypted EBS
```

You can downsize later.

Put it in a private subnet if convenient. Use **SSM Session Manager**, not public SSH.

Call it:

```text
hermes-security-lab
```

For the prototype, the instance needs outbound HTTPS to Azure, GitHub, Anthropic/OpenAI and package repositories.

Install the basics:

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y \
  git \
  curl \
  jq \
  unzip \
  python3 \
  python3-pip \
  pipx \
  docker.io
```

Then:

```bash
sudo usermod -aG docker $USER
```

Re-login afterward.

---

# 3. Install Azure CLI

Use Microsoft's current supported installation route for Ubuntu rather than improvising the package source.

After installation verify:

```bash
az version
```

You don't actually need the CLI credentials to be Prowler's permanent identity; it is useful for debugging and for the agent's contextual read-only queries.

---

# 4. Install Prowler

Use `pipx`:

```bash
pipx install prowler
pipx ensurepath
source ~/.bashrc
```

Test:

```bash
prowler --version
```

Prowler's Azure CLI supports service-principal, Azure CLI, browser, and managed-identity authentication; Prowler recommends a service principal for this use case. citeturn977779view1turn977779view3

---

# 5. Install Trivy

Install Trivy independently even though Prowler can already invoke it for IaC.

Why?

Because you want Hermes to be able to ask things like:

```bash
trivy fs ./eiger
trivy config ./eiger
trivy image eiger:latest
```

Trivy can scan filesystems for vulnerabilities, secrets and misconfiguration and scan container images for package vulnerabilities and secrets. citeturn274334search9turn274334search3

So your division becomes:

```text
Prowler        Azure posture / compliance
Trivy          code / dependency / image / IaC
Azure CLI      targeted validation/context
GitHub         source of truth
Hermes         reasoning
```

---

# 6. Install Terraform and GitHub CLI

You want Terraform available even if Eiger isn't initially built with Terraform.

Make Eiger's Azure deployment IaC-driven from the beginning.

My strong recommendation:

**Terraform, not manual Azure Portal deployment.**

The entire remediation demo gets much stronger when Hermes can say:

> “I found the configuration problem in Azure, located its source in `infra/storage.tf`, and generated this patch.”

Rather than:

> “Somebody needs to click this Azure setting.”

Also install:

```bash
gh --version
terraform version
```

---

# 7. Put Eiger in GitHub

I would structure it like this:

```text
eiger/
│
├── app/
│   ├── ...
│   └── requirements.txt
│
├── Dockerfile
│
├── infra/
│   ├── main.tf
│   ├── network.tf
│   ├── identity.tf
│   ├── storage.tf
│   ├── keyvault.tf
│   └── variables.tf
│
├── .github/
│   └── workflows/
│       └── deploy.yml
│
└── docs/
    └── architecture.md
```

This is **important for the remediation story**.

Your runtime problem in Azure should have a corresponding source-of-truth configuration in GitHub.

---

# 8. Intentionally make Eiger vulnerable

Not ridiculously vulnerable.

Make it resemble realistic configuration drift and questionable cloud architecture.

I'd seed approximately **8–10 issues**, of which 4–5 make excellent demos.

For example:

```text
Storage account public network access
Key Vault permits public access
Overprivileged managed identity
Container image with known vulnerable package
Weak NSG rule
Insufficient diagnostic logging
Storage secure-transfer/configuration issue
Excessive IAM/RBAC assignment
Secret accidentally present in application configuration
IaC configuration that created one of these conditions
```

The sweet spot is that Prowler should detect the cloud-side issue, while GitHub/Trivy reveals **why it exists and how to fix it properly**.

You want at least one chain like:

```text
Prowler:
Storage network posture issue
          ↓
Hermes:
which resource?
          ↓
Azure CLI:
confirm current configuration
          ↓
GitHub:
find corresponding Terraform
          ↓
Remediation Agent:
generate patch
          ↓
Trivy:
re-scan modified IaC
          ↓
terraform validate
          ↓
terraform plan
          ↓
SRE Agent:
assess blast radius
          ↓
Remediation Package
```

That will demonstrate the thesis beautifully.

---

# 9. Create the Prowler identity in Azure

Create a dedicated application/service principal:

```bash
az ad sp create-for-rbac \
  --name "eiger-prowler-readonly"
```

Prowler documents exactly this method for creating its service principal. citeturn977779view2

Save:

```text
tenant ID
client ID
client secret
subscription ID
```

Do **not** use your personal Azure identity as the permanent integration.

At subscription scope assign:

```text
Reader
```

Prowler additionally documents its custom `ProwlerRole` for checks requiring extra read-oriented permissions. citeturn977779view1

For this prototype I would **skip Graph/Entra permissions initially** unless the findings you want require them. Prowler says those permissions enhance Entra checks but are not mandatory for basic Azure execution. citeturn977779view1

That keeps the initial model very clean:

> cloud infrastructure read-only.

---

# 10. Store the Azure credentials on the Hermes host

Don't scatter them through shell history.

Use AWS Secrets Manager eventually.

For the first run, load the Prowler-required environment values into a protected environment file used by the scanning process.

Then test:

```bash
prowler azure --sp-env-auth
```

Azure requires an explicit authentication method, and `--sp-env-auth` is Prowler's documented service-principal route. citeturn977779view3

Limit to your Eiger subscription:

```bash
prowler azure \
  --sp-env-auth \
  --subscription-ids <EIGER_SUBSCRIPTION_ID>
```

---

# 11. First major milestone: don't install Hermes yet

Seriously.

Before involving an agent, prove the deterministic substrate.

Your first successful workflow should simply be:

```bash
prowler azure \
  --sp-env-auth \
  --subscription-ids <SUBSCRIPTION_ID>
```

Prowler generates CSV, HTML and JSON-OCSF output by default. citeturn977779view3

Create:

```text
/opt/security-platform/
│
├── data/
│   └── eiger/
│       ├── prowler/
│       ├── trivy/
│       ├── azure/
│       ├── github/
│       └── remediation/
│
├── repos/
│   └── eiger/
│
├── workflows/
│
├── schemas/
│
└── agents/
```

Put the Prowler JSON-OCSF output under:

```text
data/eiger/prowler/
```

Now inspect it manually.

Pick **five findings that are genuinely interesting**.

---

# 12. Connect GitHub read-only

Initially use a **fine-grained GitHub PAT** restricted to the Eiger repo and read-only access.

GitHub recommends fine-grained tokens because their access can be narrowed to selected repositories and permissions. citeturn274334search12turn274334search5

Clone:

```bash
cd /opt/security-platform/repos
git clone <EIGER_REPO>
```

For the first phase, the agent should **not have push access**.

Have Hermes write proposed patches somewhere like:

```text
/data/eiger/remediation/REM-001/eiger.patch
```

Then you inspect them.

Later move it to GitHub PR creation.

---

# 13. Run Trivy manually

Against the repo:

```bash
trivy fs /opt/security-platform/repos/eiger \
  --format json \
  --output /opt/security-platform/data/eiger/trivy/fs.json
```

Then IaC:

```bash
trivy config /opt/security-platform/repos/eiger \
  --format json \
  --output /opt/security-platform/data/eiger/trivy/config.json
```

If Eiger is containerized:

```bash
trivy image <EIGER_IMAGE> \
  --format json \
  --output /opt/security-platform/data/eiger/trivy/image.json
```

Now you have:

```text
Cloud reality        → Prowler
Source/IaC           → GitHub
Software/container   → Trivy
```

---

# 14. Install Hermes

Only now.

Official Linux installation:

```bash
curl -fsSL \
  https://hermes-agent.nousresearch.com/install.sh \
  | bash
```

Then:

```bash
source ~/.bashrc
hermes setup
```

Hermes' current official quickstart uses that installer and recommends getting one normal conversation working before layering on skills, profiles, cron, etc. citeturn977779view0

Configure your strongest available reasoning model.

Then test:

```bash
hermes
```

Ask:

> Read `/opt/security-platform/data/eiger/prowler/`. Tell me the five most important Azure findings and explain why.

At this point **do not let it execute anything**.

You're checking reasoning quality first.

---

# 15. Give Hermes local CLI access

This is where Hermes becomes useful.

I would eventually use Hermes' Docker terminal backend rather than unrestricted execution on the host. Hermes currently supports local, Docker and several remote/sandbox execution backends. citeturn977779view4

Conceptually:

```text
Hermes
   │
   ├── Prowler CLI
   ├── Trivy CLI
   ├── Azure CLI READ ONLY
   ├── git READ ONLY
   ├── terraform validate
   └── terraform plan
```

Initially I would **not use MCP for any of these**.

Shell commands are adequate and much easier to debug.

---

# 16. Build only ONE Hermes skill first

Call it:

```text
azure-remediation-engineer
```

Its job:

> Take one validated Prowler finding and produce an evidence-backed remediation package.

The workflow should be explicitly prescribed:

```text
1. Read Prowler finding.

2. Verify finding against live Azure
   using read-only Azure APIs.

3. Identify affected resource.

4. Identify relevant repository/IaC.

5. Establish whether the live configuration
   is managed by IaC.

6. Determine root cause.

7. Develop candidate remediation.

8. Determine security impact.

9. Determine production dependencies.

10. Challenge proposed remediation
    for potential breakage.

11. Generate proposed source change.

12. Run:
       terraform fmt
       terraform validate
       terraform plan
       Trivy IaC scan

13. Determine rollback.

14. Determine post-deployment validation.

15. Emit structured RemediationPackage.

16. Never modify Azure.
17. Never push Git changes.
18. If evidence is insufficient:
       return NEEDS_HUMAN_CONTEXT.
```

That last part is extremely important.

---

# 17. Don't create five agents immediately

I've changed my view slightly for the prototype.

Start with **one agent executing five roles sequentially**.

Why?

Because you'll debug:

```text
data flow
permissions
Prowler parsing
Terraform
Git access
Azure access
prompting
Hermes
```

You do not need distributed-agent orchestration problems at the same time.

Have Hermes explicitly perform:

```text
SECURITY ANALYST
       ↓
REMEDIATION ENGINEER
       ↓
SRE REVIEWER
       ↓
SECURITY REVIEWER
       ↓
CHANGE MANAGER
```

But all within one controlled workflow.

Once it works, split those roles into independent Hermes profiles.

Hermes profiles can isolate configuration, memory, skills and credentials, so that is a natural second-stage architecture. citeturn274334search1

---

# 18. Create the RemediationPackage schema now

Do this before polishing prompts.

Something like:

```json
{
  "remediation_id": "REM-AZ-001",
  "finding": {
    "source": "prowler",
    "check_id": "",
    "title": "",
    "resource_id": ""
  },

  "validation": {
    "finding_confirmed": true,
    "evidence": [],
    "confidence": 0.0
  },

  "risk": {
    "severity": "",
    "business_context": "",
    "attack_scenario": ""
  },

  "source_of_truth": {
    "type": "terraform",
    "repository": "",
    "files": []
  },

  "remediation": {
    "objective": "",
    "approach": "",
    "patch_file": ""
  },

  "production_impact": {
    "expected": "",
    "dependencies": [],
    "unknowns": [],
    "risk": ""
  },

  "preflight": {
    "terraform_validate": "",
    "terraform_plan": "",
    "trivy": ""
  },

  "deployment": {
    "steps": [],
    "recommended_window": "",
    "approval_required": true
  },

  "rollback": {
    "trigger_conditions": [],
    "steps": []
  },

  "verification": {
    "security_checks": [],
    "application_checks": [],
    "monitoring": []
  },

  "status": "READY_FOR_REVIEW"
}
```

This will become far more important than the Hermes prompts.

---

# 19. Your first end-to-end test

Choose one Prowler finding.

For example:

```text
Azure Storage Account
public network access enabled
```

Tell Hermes:

> Process Prowler finding X through the Azure remediation workflow. Use the live Azure environment and Eiger GitHub repository as evidence. Do not make any external changes.

Hermes should:

```text
Prowler finding
      ↓
az resource/storage query
      ↓
confirm problem
      ↓
search Eiger Terraform
      ↓
find resource declaration
      ↓
understand dependencies
      ↓
propose Terraform change
      ↓
make change ONLY in working copy
      ↓
terraform validate
      ↓
terraform plan
      ↓
Trivy scan
      ↓
analyze expected blast radius
      ↓
produce rollback
      ↓
produce RemediationPackage
```

**That is milestone #1.**

Nothing else matters until this works reliably.

---

# 20. Then make the SRE challenge explicit

Once the first pipeline works, introduce a second pass:

> You are now the production SRE. Your responsibility is availability, not security. Assume the remediation engineer may have overlooked dependencies. Attempt to prove that this change could cause an outage.

Return:

```text
APPROVE
REJECT
NEEDS_MORE_EVIDENCE
```

If rejected:

```text
Remediation Engineer
        ↑
        │
SRE objections
```

Then iterate.

This is where the system starts looking much more sophisticated than Copilot summarizing Prowler.

---

# 21. Then allow a working-copy patch

Hermes should be allowed to modify:

```text
/opt/security-platform/workspaces/eiger/REM-001/
```

but **not your canonical cloned repo** and not GitHub.

Run:

```bash
terraform fmt -check
terraform validate
terraform plan
trivy config .
```

Store all output as evidence.

Now you can show the customer:

**Before**

```hcl
public_network_access_enabled = true
```

**After**

```hcl
public_network_access_enabled = false
```

alongside the successful plan and security reassessment.

That is compelling.

---

# 22. Add GitHub PR generation second

Once patch generation is good, graduate the agent from:

```text
L2: recommend
```

to:

```text
L3: prepare change
```

Give a separate GitHub identity permission to:

```text
create branch
commit to agent branch
open PR
```

but **never merge**.

Then your demo ends with:

```text
Prowler finding

   ↓ 3m 22s

Validated

   ↓

Impact assessed

   ↓

Remediation agreed

   ↓

Terraform patch generated

   ↓

Plan passed

   ↓

Trivy passed

   ↓

Rollback generated

   ↓

PR #47 opened

       [VIEW PR]
```

That's probably the strongest three-day prototype you can realistically produce.

---

# 23. Only after that split Hermes into agents

Eventually:

```text
                 Orchestrator
                      │
       ┌──────────────┼───────────────┐
       ▼              ▼               ▼
 Security Analyst   SRE Agent    Compliance Agent
       │              │               │
       └──────────────┼───────────────┘
                      ▼
             Remediation Engineer
                      │
                      ▼
                 Change Agent
```

And the privileges should be different.

For example:

```text
Security Analyst
Azure READ
Prowler
Trivy
GitHub READ

SRE
Azure READ
metrics/logs READ
GitHub READ

Remediation Engineer
GitHub working tree WRITE
NO Azure write

Change Agent
GitHub PR create
NO Azure write

Deployment Agent — future
only approved pipeline execution
```

This is far safer than giving “Hermes” a giant credential containing everything.

---

# 24. What I would build in the next three days

**Day 1:** deploy Eiger into Azure using Terraform; intentionally introduce 5 useful cloud issues; provision read-only Prowler service principal; get Prowler scanning successfully; get Trivy scanning repo/IaC/container; clone GitHub repo onto AWS box.

**Day 2:** install Hermes; create `azure-remediation-engineer`; implement the RemediationPackage schema; get **one finding completely through finding → validation → GitHub source → patch → Terraform plan → Trivy → impact → rollback**. Then repeat against three more findings.

**Day 3:** add the SRE challenge/revision cycle, enable PR generation if stable, and put a lightweight UI around the saved remediation packages. Keep all five demo scenarios precomputed so the presentation isn't hostage to an LLM/API call.

## The demo I would target

The customer sees:

```text
EIGER — Azure

Prowler scan
────────────
47 findings

AI triage
─────────
4 critical remediation candidates
11 high
20 contextual / low priority
12 suppressed


TOP REMEDIATION

Public access path to application secrets

[Prowler evidence]

        ↓

Agent investigation

✓ Azure configuration validated
✓ Terraform source found
✓ 3 dependent services identified
✓ remediation generated
✓ SRE challenge passed
✓ Terraform plan successful
✓ Trivy validation passed
✓ rollback validated

STATUS

READY FOR CHANGE


[VIEW REMEDIATION]
[VIEW EVIDENCE]
[VIEW PATCH]
[CREATE PR]
```

And the sentence I'd use to frame it is:

> **“Prowler tells us what is wrong. This platform figures out how to safely make it right.”**

That is the prototype I would build before adding CTEM or expanding into a broader multi-cloud platform.

