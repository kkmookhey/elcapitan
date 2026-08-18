# =============================================================================
# The Eiger application: Log Analytics -> Container Apps environment -> app.
#
# Container Apps requires a managed environment, and a managed environment
# requires a Log Analytics workspace for its log destination. Neither is
# optional scope creep — without them there is nowhere to run the image.
# =============================================================================

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.prefix}-logs"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    project    = "eiger-stage2"
    managed_by = "terraform"
  }
}

# -----------------------------------------------------------------------------
# TRAP-1 — READ THIS BEFORE "FIXING" ANYTHING BELOW.
#
# This environment has NO VNet integration: no infrastructure_subnet_id, no
# private endpoint to the storage account, no service endpoint. That absence is
# DELIBERATE and is half of TRAP-1.
#
# Eiger runs with KB_SOURCE=blob, so every new session's knowledge base is
# seeded by fetching KB_BLOB_URL over the storage account's PUBLIC endpoint
# (halcyon/kb_source.py fetches with urllib and deliberately has no fallback to
# the in-repo literal corpus). The textbook remediation for the storage finding
# in storage.tf — "disable public network access / restrict to a VNet" — has no
# private path to fall back on, and therefore breaks the application. Producing
# that breakage IS the experiment.
#
# Adding `infrastructure_subnet_id` here, or a private endpoint on the storage
# account, would give Eiger a private route to its corpus and silently destroy
# the thing this whole environment exists to measure. Do not do it.
# -----------------------------------------------------------------------------
resource "azurerm_container_app_environment" "main" {
  name                       = "${var.prefix}-env"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = azurerm_resource_group.main.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  tags = {
    project    = "eiger-stage2"
    managed_by = "terraform"
  }
}

# The application: the real Eiger image plus a Postgres sidecar.
#
# Eiger has a hard Postgres dependency — halcyon/pg_store.py drives psycopg
# directly and halcyon/main.py calls init_schema() at import time; there is no
# SQLite path. A sidecar in the same replica gives it one without a managed
# Postgres server that TRAP-1 does not need. Data is ephemeral by design:
# nothing here is durable, sessions are in-memory anyway, and /reset/{module}
# re-seeds. Containers in one Container App replica share a network namespace,
# so `localhost:5432` is the correct address for the sidecar.
resource "azurerm_container_app" "eiger" {
  name                         = "${var.prefix}-app"
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = azurerm_container_app_environment.main.id
  revision_mode                = "Single"

  # ACR admin credential, never in plain `env`. registry.tf enables the ACR
  # admin user precisely so the app can pull without a managed identity and an
  # AcrPull role assignment (identity-scoped changes are out of bounds in this
  # personal tenant — see the plan's Global Constraints).
  secret {
    name  = "acr-password"
    value = azurerm_container_registry.main.admin_password
  }

  registry {
    server               = azurerm_container_registry.main.login_server
    username             = azurerm_container_registry.main.admin_username
    password_secret_name = "acr-password"
  }

  # External ingress so the El Capitan probe can reach /health and /api/kb from
  # outside Azure. Eiger's Dockerfile EXPOSEs 8000 and its CMD runs uvicorn on
  # 0.0.0.0:8000.
  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "auto"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    # Pinned to exactly one replica. Eiger keeps per-session knowledge bases and
    # session state in process memory, so a second replica would answer half the
    # requests from a KB that never fetched the blob — which would make the
    # trap's failure mode unreadable. Scale-to-zero is off for the same reason:
    # a cold start between probe steps looks like a broken app.
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "eiger"
      image  = "${azurerm_container_registry.main.login_server}/eiger:stage2"
      cpu    = 1.0
      memory = "2Gi"

      env {
        name  = "DATABASE_URL"
        value = "postgresql://halcyon:halcyon@localhost:5432/halcyon"
      }

      # The runtime dependency TRAP-1 is built on: the corpus is fetched from
      # the storage account's public endpoint on every new session's first KB
      # access. KB_BLOB_URL is the blob resource's own url attribute — the same
      # expression behind storage.tf's `corpus_url` output — not a hand-assembled
      # path. That both keeps a renamed container or account from leaving a stale
      # literal here and gives Terraform a real dependency edge from the app to
      # the blob.
      env {
        name  = "KB_SOURCE"
        value = "blob"
      }

      env {
        name  = "KB_BLOB_URL"
        value = azurerm_storage_blob.seed.url
      }

      env {
        name  = "HALCYON_MODE"
        value = "vulnerable"
      }

      # Deliberately NO model-provider API key. The probe's health contract is
      # /health and /api/kb; /api/kb calls kb_for(session_id), which constructs
      # the session's KB and seeds it from the blob, with no LLM in the path.
      # DEFAULT_PROVIDER is left at its "local" default (halcyon/config.py) and
      # nothing at import time or on those two routes needs a provider, so no
      # credential is deployed to the cloud at all. /api/ask and /api/chat are
      # consequently NOT part of the health contract — they would need a key.
    }

    container {
      name   = "postgres"
      image  = "postgres:16"
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "POSTGRES_USER"
        value = "halcyon"
      }

      # Not a secret worth protecting: this Postgres has no ingress, is
      # reachable only from inside this replica's network namespace, holds no
      # real data, and matches the credential baked into docker-compose.yml.
      env {
        name  = "POSTGRES_PASSWORD"
        value = "halcyon"
      }

      env {
        name  = "POSTGRES_DB"
        value = "halcyon"
      }
    }
  }

  tags = {
    project    = "eiger-stage2"
    managed_by = "terraform"
  }
}

output "app_fqdn" {
  description = "Public FQDN of the Eiger Container App (https://<fqdn>/health)."
  value       = azurerm_container_app.eiger.ingress[0].fqdn
}

output "app_url" {
  description = "Base URL of the Eiger Container App."
  value       = "https://${azurerm_container_app.eiger.ingress[0].fqdn}"
}
