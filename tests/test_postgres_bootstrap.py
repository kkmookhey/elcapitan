import pytest

from elcapitan.postgres_bootstrap import BootstrapTarget


HOST = "elcapitan-pilot.postgres.database.azure.com"
ADMIN_URL = f"postgresql://admin:secret@{HOST}/postgres?sslmode=require"


def environment(**overrides):
    values = {
        "ELCAPITAN_BOOTSTRAP_ADMIN_URL": ADMIN_URL,
        "ELCAPITAN_BOOTSTRAP_APP_PASSWORD": "a" * 40,
    }
    values.update(overrides)
    return values


def test_bootstrap_target_is_bound_to_confirmed_private_server():
    target = BootstrapTarget.from_environment(
        expected_host=HOST, role="elcapitan_customer", database="elcapitan_customer",
        confirmation="CREATE-ISOLATED-DATABASE", environment=environment(),
    )

    assert target.host == HOST
    assert "sslmode=require" in target.app_dsn
    assert "dbname=elcapitan_customer" in target.admin_database_dsn
    assert "a" * 40 not in repr(target)


@pytest.mark.parametrize("confirmation", ["", "create", "CREATE"])
def test_bootstrap_rejects_missing_confirmation(confirmation):
    with pytest.raises(ValueError, match="confirmation"):
        BootstrapTarget.from_environment(
            expected_host=HOST, role="elcapitan_customer", database="elcapitan_customer",
            confirmation=confirmation, environment=environment(),
        )


def test_bootstrap_rejects_cross_host_admin_url():
    with pytest.raises(ValueError, match="outside the confirmed host"):
        BootstrapTarget.from_environment(
            expected_host=HOST, role="elcapitan_customer", database="elcapitan_customer",
            confirmation="CREATE-ISOLATED-DATABASE",
            environment=environment(
                ELCAPITAN_BOOTSTRAP_ADMIN_URL=(
                    "postgresql://admin:secret@other.postgres.database.azure.com/"
                    "postgres?sslmode=require")),
        )


def test_bootstrap_requires_tls_and_strong_app_password():
    with pytest.raises(ValueError, match="at least 32"):
        BootstrapTarget.from_environment(
            expected_host=HOST, role="elcapitan_customer", database="elcapitan_customer",
            confirmation="CREATE-ISOLATED-DATABASE",
            environment=environment(ELCAPITAN_BOOTSTRAP_APP_PASSWORD="short"),
        )
    with pytest.raises(ValueError, match="require TLS"):
        BootstrapTarget.from_environment(
            expected_host=HOST, role="elcapitan_customer", database="elcapitan_customer",
            confirmation="CREATE-ISOLATED-DATABASE",
            environment=environment(
                ELCAPITAN_BOOTSTRAP_ADMIN_URL=(
                    f"postgresql://admin:secret@{HOST}/postgres?sslmode=prefer")),
        )
