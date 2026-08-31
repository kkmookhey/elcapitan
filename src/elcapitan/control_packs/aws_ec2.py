"""Deterministic AWS EC2 security-group control definitions."""
from __future__ import annotations

import ipaddress

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


_RULE_KEYS = frozenset({
    "protocol", "from_port", "to_port", "ipv4_cidrs", "ipv6_cidrs",
})
_HIGH_RISK_PORTS = (25, 110, 135, 143, 445, 3000, 4333, 5000, 5500, 8080, 8088)
_PORT_CONTROLS = (
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", (22,), "SSH"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389", (3389,), "RDP"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888", (7199, 9160, 8888), "Cassandra"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601", (9200, 9300, 5601), "Elasticsearch/Kibana"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_ftp_20_21", (20, 21), "FTP"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092", (9092,), "Kafka"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211", (11211,), "Memcached"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018", (27017, 27018), "MongoDB"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306", (3306,), "MySQL"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483", (1521, 2483), "Oracle"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432", (5432,), "PostgreSQL"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379", (6379,), "Redis"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434", (1433, 1434), "SQL Server"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23", (23,), "Telnet"),
)


def _bool(values, aspect: str) -> bool:
    value = require(values, aspect)
    if not isinstance(value, bool):
        raise ValueError(f"live EC2 state has invalid {aspect} {value!r}")
    return value


def _name(values) -> str:
    value = require(values, "ec2_sg_name")
    if not isinstance(value, str) or not value:
        raise ValueError(f"live EC2 state has invalid security-group name {value!r}")
    return value


def _rules(values, aspect: str) -> list[dict]:
    value = require(values, aspect)
    if not isinstance(value, list):
        raise ValueError(f"live EC2 state has invalid {aspect} {value!r}")
    for rule in value:
        if not isinstance(rule, dict) or set(rule) != _RULE_KEYS:
            raise ValueError(f"live EC2 state has invalid {aspect} rule {rule!r}")
        protocol = rule["protocol"]
        start = rule["from_port"]
        end = rule["to_port"]
        if not isinstance(protocol, str) or not protocol:
            raise ValueError(f"live EC2 state has invalid rule protocol {protocol!r}")
        if (start is None) != (end is None):
            raise ValueError("live EC2 state has an incomplete port range")
        if start is not None and (
                isinstance(start, bool) or isinstance(end, bool)
                or not isinstance(start, int) or not isinstance(end, int)
                or start < -1 or end > 65535 or start > end):
            raise ValueError(f"live EC2 state has invalid port range {start!r}-{end!r}")
        for field, version in (("ipv4_cidrs", 4), ("ipv6_cidrs", 6)):
            cidrs = rule[field]
            if (not isinstance(cidrs, list)
                    or any(not isinstance(item, str) or not item for item in cidrs)
                    or len(cidrs) != len(set(cidrs))):
                raise ValueError(f"live EC2 state has invalid {field} {cidrs!r}")
            for cidr in cidrs:
                try:
                    network = ipaddress.ip_network(cidr)
                except ValueError as exc:
                    raise ValueError(
                        f"live EC2 state has invalid CIDR {cidr!r}") from exc
                if network.version != version:
                    raise ValueError(f"live EC2 state has invalid {field} CIDR {cidr!r}")
    return value


def _wildcard(rule: dict) -> bool:
    return ("0.0.0.0/0" in rule["ipv4_cidrs"]
            or "::/0" in rule["ipv6_cidrs"])


def _opens_all_ports(rule: dict) -> bool:
    if not _wildcard(rule):
        return False
    return (rule["protocol"] == "-1"
            or (rule["from_port"] == 0 and rule["to_port"] == 65535))


def _in_scope(values) -> bool:
    return _bool(values, "ec2_sg_in_use")


def _all_ports(values) -> ControlEvaluation:
    rules = _rules(values, "ec2_sg_ingress_rules")
    if not _in_scope(values):
        return ControlEvaluation(
            confirmed=False,
            reason="security group is unused and excluded by Prowler's default scope",
        )
    exposed = any(_opens_all_ports(rule) for rule in rules)
    return ControlEvaluation(
        confirmed=exposed,
        reason=("security group exposes all ports to a wildcard internet CIDR"
                if exposed else "security group does not expose all ports to the internet"),
    )


def _ports_evaluator(ports: tuple[int, ...], label: str):
    def evaluate(values) -> ControlEvaluation:
        rules = _rules(values, "ec2_sg_ingress_rules")
        if not _in_scope(values):
            return ControlEvaluation(
                confirmed=False,
                reason="security group is unused and excluded by Prowler's default scope",
            )
        if any(_opens_all_ports(rule) for rule in rules):
            return ControlEvaluation(
                confirmed=False,
                reason=("Prowler suppresses the specific-port finding when its "
                        "all-ports control is active"),
            )
        exposed = any(
            _wildcard(rule)
            and rule["protocol"] == "tcp"
            and rule["from_port"] is not None
            and any(rule["from_port"] <= port <= rule["to_port"] for port in ports)
            for rule in rules
        )
        return ControlEvaluation(
            confirmed=exposed,
            reason=(f"security group exposes {label} TCP port(s) to the internet"
                    if exposed else
                    f"security group does not expose {label} TCP port(s) to the internet"),
        )
    return evaluate


def _high_risk(values) -> ControlEvaluation:
    return _ports_evaluator(_HIGH_RISK_PORTS, "configured high-risk")(values)


def _wide_open_public_ipv4(values) -> ControlEvaluation:
    ingress = _rules(values, "ec2_sg_ingress_rules")
    egress = _rules(values, "ec2_sg_egress_rules")
    if not _in_scope(values):
        return ControlEvaluation(
            confirmed=False,
            reason="security group is unused and excluded by Prowler's default scope",
        )
    exposed = False
    for rule in (*ingress, *egress):
        for cidr in rule["ipv4_cidrs"]:
            network = ipaddress.ip_network(cidr)
            if network.is_global and 0 < network.prefixlen < 24:
                exposed = True
                break
        if exposed:
            break
    return ControlEvaluation(
        confirmed=exposed,
        reason=("security group contains a globally routable IPv4 range broader than /24"
                if exposed else
                "security group has no globally routable IPv4 range broader than /24"),
    )


def _default_restrict(values) -> ControlEvaluation:
    ingress = _rules(values, "ec2_sg_ingress_rules")
    egress = _rules(values, "ec2_sg_egress_rules")
    name = _name(values)
    if not _in_scope(values) or name != "default":
        return ControlEvaluation(
            confirmed=False,
            reason="control applies only to an in-use default security group",
        )
    allows_traffic = bool(ingress or egress)
    return ControlEvaluation(
        confirmed=allows_traffic,
        reason=("default security group has traffic rules" if allows_traffic else
                "default security group has no traffic rules"),
    )


def _many_rules(values) -> ControlEvaluation:
    ingress = _rules(values, "ec2_sg_ingress_rules")
    egress = _rules(values, "ec2_sg_egress_rules")
    excessive = len(ingress) > 50 or len(egress) > 50
    return ControlEvaluation(
        confirmed=excessive,
        reason=(f"security group has {len(ingress)} ingress and {len(egress)} "
                "egress permission entries"),
    )


def _launch_wizard(values) -> ControlEvaluation:
    name = _name(values)
    created_by_wizard = "launch-wizard" in name
    return ControlEvaluation(
        confirmed=created_by_wizard,
        reason=f"security-group name is {name!r}",
    )


def _control(rule_id: str, aspects: tuple[str, ...], evaluator) -> ControlDefinition:
    return ControlDefinition(
        pack_id="aws-ec2-security-group", provider="aws", rule_id=rule_id,
        resource_family="ec2_security_group",
        resource_types=("awsec2securitygroup",),
        live_validation=True, remediation_planning=False, live_execution=False,
        evidence_aspects=aspects, evaluator=evaluator,
        evidence_grade="contract_tested",
    )


_INGRESS_SCOPE = ("ec2_sg_in_use", "ec2_sg_ingress_rules")

AWS_EC2_SECURITY_GROUP_PACK = ControlPack(
    pack_id="aws-ec2-security-group",
    evidence_grade="contract_tested",
    controls=(
        _control(
            "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
            _INGRESS_SCOPE, _all_ports),
        _control(
            "ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports",
            _INGRESS_SCOPE, _high_risk),
        *(
            _control(rule_id, _INGRESS_SCOPE, _ports_evaluator(ports, label))
            for rule_id, ports, label in _PORT_CONTROLS
        ),
        _control(
            "ec2_securitygroup_allow_wide_open_public_ipv4",
            ("ec2_sg_in_use", "ec2_sg_ingress_rules", "ec2_sg_egress_rules"),
            _wide_open_public_ipv4),
        _control(
            "ec2_securitygroup_default_restrict_traffic",
            ("ec2_sg_in_use", "ec2_sg_name", "ec2_sg_ingress_rules",
             "ec2_sg_egress_rules"),
            _default_restrict),
        _control(
            "ec2_securitygroup_from_launch_wizard",
            ("ec2_sg_name",), _launch_wizard),
        _control(
            "ec2_securitygroup_with_many_ingress_egress_rules",
            ("ec2_sg_ingress_rules", "ec2_sg_egress_rules"), _many_rules),
    ),
)
