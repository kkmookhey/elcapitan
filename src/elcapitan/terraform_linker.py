"""Conservative cloud-resource to Terraform source linking.

The first product slice supports literal declarations and exact resource IDs
from Terraform state. It refuses ambiguous matches instead of asking an agent
to guess which block owns a live resource.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .hashing import canonical_json, sha256_bytes, sha256_file


_IGNORED_DIRECTORIES = frozenset({
    ".git", ".terraform", ".venv", ".tox", ".pytest_cache", "__pycache__",
})
_RESOURCE_HEADER = re.compile(
    r'^\s*resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{'
)
_LITERAL_ASSIGNMENT = re.compile(
    r'^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(?P<value>(?:[^"\\]|\\.)*)"',
    re.MULTILINE,
)
_AZURE_TYPES = {
    ("microsoft.storage", "storageaccounts"): "azurerm_storage_account",
    ("microsoft.web", "sites"): "azurerm_linux_web_app",
    ("microsoft.app", "containerapps"): "azurerm_container_app",
    ("microsoft.keyvault", "vaults"): "azurerm_key_vault",
}


class TerraformLinkError(ValueError):
    pass


class TerraformLinkNotFound(TerraformLinkError):
    pass


class AmbiguousTerraformLink(TerraformLinkError):
    pass


@dataclass(frozen=True)
class TerraformLink:
    resource_uid: str
    source_path: str
    module_path: str
    resource_type: str
    resource_name: str
    start_line: int
    end_line: int
    match_strategy: str
    confidence: float
    source_sha256: str
    resource_address: str = ""
    state_sha256: str = ""

    def to_dict(self) -> dict:
        return {
            "resource_uid": self.resource_uid,
            "source_path": self.source_path,
            "module_path": self.module_path,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "match_strategy": self.match_strategy,
            "confidence": self.confidence,
            "source_sha256": self.source_sha256,
            "resource_address": self.resource_address,
            "state_sha256": self.state_sha256,
        }


@dataclass(frozen=True)
class _CloudIdentity:
    terraform_type: str | None
    name: str
    resource_group: str = ""


@dataclass(frozen=True)
class _Block:
    source_path: Path
    resource_type: str
    resource_name: str
    start_line: int
    end_line: int
    text: str


def _cloud_identity(provider: str, resource_uid: str) -> _CloudIdentity:
    provider = provider.lower()
    if provider == "azure":
        match = re.search(
            r"/resourceGroups/(?P<group>[^/]+)/providers/(?P<namespace>[^/]+)/"
            r"(?P<type>[^/]+)/(?P<name>[^/]+)",
            resource_uid,
            re.IGNORECASE,
        )
        if not match:
            return _CloudIdentity(None, "")
        key = (match.group("namespace").lower(), match.group("type").lower())
        return _CloudIdentity(
            _AZURE_TYPES.get(key), match.group("name"), match.group("group")
        )
    if provider == "aws":
        s3 = re.fullmatch(r"arn:(?:aws|aws-us-gov|aws-cn):s3:::(?P<name>[^/]+)", resource_uid)
        if s3:
            return _CloudIdentity("aws_s3_bucket", s3.group("name"))
    return _CloudIdentity(None, "")


def _terraform_files(root: Path) -> tuple[Path, ...]:
    files: list[Path] = []
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            name for name in directories
            if name not in _IGNORED_DIRECTORIES
            and not (current_path / name).is_symlink()
        )
        for name in sorted(names):
            path = current_path / name
            if path.suffix == ".tf" and not path.is_symlink() and path.is_file():
                files.append(path)
    return tuple(files)


def _brace_delta(line: str) -> int:
    """Count structural braces while ignoring strings and line comments."""
    delta = 0
    quoted = False
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted and char == "#":
            break
        elif not quoted and line[index:index + 2] == "//":
            break
        elif not quoted and char == "{":
            delta += 1
        elif not quoted and char == "}":
            delta -= 1
        index += 1
    return delta


def _blocks(path: Path) -> tuple[_Block, ...]:
    if path.stat().st_size > 2 * 1024 * 1024:
        raise TerraformLinkError(f"Terraform source is too large to inspect safely: {path}")
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    blocks: list[_Block] = []
    index = 0
    while index < len(lines):
        header = _RESOURCE_HEADER.match(lines[index])
        if not header:
            index += 1
            continue
        start = index
        depth = 0
        while index < len(lines):
            depth += _brace_delta(lines[index])
            index += 1
            if depth == 0:
                break
        if depth != 0:
            raise TerraformLinkError(
                f"unterminated Terraform resource block at {path}:{start + 1}"
            )
        blocks.append(_Block(
            source_path=path,
            resource_type=header.group("type"),
            resource_name=header.group("name"),
            start_line=start + 1,
            end_line=index,
            text="".join(lines[start:index]),
        ))
    return tuple(blocks)


def terraform_resource_block(path, *, resource_type: str,
                             resource_name: str) -> str:
    """Return one exact Terraform resource block from a verified source file.

    Execution drivers use this to bind a provider operation to the same block
    selected during planning.  Ambiguity is an error; a driver must never
    infer which of several similarly named resources an approved plan meant.
    """
    source = Path(path).resolve(strict=True)
    matches = [
        block.text for block in _blocks(source)
        if block.resource_type == resource_type and block.resource_name == resource_name
    ]
    if len(matches) != 1:
        raise TerraformLinkError(
            f"expected exactly one {resource_type}.{resource_name} block in {source}; "
            f"found {len(matches)}"
        )
    return matches[0]


def _literal_values(block: _Block) -> dict[str, str]:
    return {
        match.group("name"): match.group("value").replace(r'\"', '"').replace(r"\\", "\\")
        for match in _LITERAL_ASSIGNMENT.finditer(block.text)
    }


def _state_resources(document: Mapping) -> tuple[tuple[str, str, str, Mapping], ...]:
    """Flatten `terraform show -json` and raw state resource representations."""
    found: list[tuple[str, str, str, Mapping]] = []

    def visit_module(module: Mapping) -> None:
        for resource in module.get("resources", ()):
            values = resource.get("values") or {}
            found.append((
                str(resource.get("address") or ""),
                str(resource.get("type") or ""),
                str(resource.get("name") or ""),
                values,
            ))
        for child in module.get("child_modules", ()):
            visit_module(child)

    values = document.get("values")
    if isinstance(values, Mapping) and isinstance(values.get("root_module"), Mapping):
        visit_module(values["root_module"])

    for resource in document.get("resources", ()):
        if resource.get("mode", "managed") != "managed":
            continue
        for index, instance in enumerate(resource.get("instances", ())):
            attributes = instance.get("attributes") or {}
            prefix = f"{resource.get('module')}." if resource.get("module") else ""
            base = f"{prefix}{resource.get('type', '')}.{resource.get('name', '')}"
            index_key = instance.get("index_key", index)
            if isinstance(index_key, str):
                suffix = f"[{json.dumps(index_key)}]"
            else:
                suffix = f"[{index_key}]"
            address = (
                base + suffix
                if "index_key" in instance or len(resource.get("instances", ())) > 1
                else base
            )
            found.append((
                address, str(resource.get("type") or ""),
                str(resource.get("name") or ""), attributes,
            ))
    return tuple(found)


def _state_identity_matches(*, provider: str, resource_uid: str,
                            resource_type: str, values: Mapping) -> bool:
    candidate = values.get("id")
    if isinstance(candidate, str) and candidate.lower() == resource_uid.lower():
        return True
    identity = _cloud_identity(provider, resource_uid)
    if (provider.lower() == "aws"
            and resource_type in {"aws_s3_bucket", "aws_s3_bucket_versioning"}
            and identity.name):
        state_names = (values.get("bucket"), candidate)
        return any(
            isinstance(value, str)
            and value.split(",", 1)[0].lower() == identity.name.lower()
            for value in state_names
        )
    return False


def _state_owner(document: Mapping, *, provider: str, resource_uid: str,
                 resource_types: tuple[str, ...]
                 ) -> tuple[str, str, str] | None:
    matches = []
    for address, resource_type, resource_name, values in _state_resources(document):
        if resource_types and resource_type not in resource_types:
            continue
        if _state_identity_matches(
                provider=provider, resource_uid=resource_uid,
                resource_type=resource_type, values=values):
            matches.append((address, resource_type, resource_name))
    if len(matches) > 1:
        addresses = ", ".join(sorted(match[0] for match in matches))
        raise AmbiguousTerraformLink(
            f"multiple Terraform state resources have id {resource_uid}: {addresses}"
        )
    return matches[0] if matches else None


def _candidate(block: _Block, *, provider: str, resource_uid: str,
               identity: _CloudIdentity,
               resource_types: tuple[str, ...]) -> tuple[str, float] | None:
    if resource_types and block.resource_type not in resource_types:
        return None
    values = _literal_values(block)
    if any(value.lower() == resource_uid.lower() for value in values.values()):
        return "exact_resource_uid", 1.0
    eligible_types = resource_types or tuple(filter(None, (identity.terraform_type,)))
    if eligible_types and block.resource_type not in eligible_types:
        return None
    if not eligible_types:
        return None
    name_attribute = "bucket" if provider.lower() == "aws" else "name"
    if values.get(name_attribute, "").lower() != identity.name.lower():
        return None
    if provider.lower() == "azure" and values.get("resource_group_name"):
        if values["resource_group_name"].lower() != identity.resource_group.lower():
            return None
        return "provider_type_name_and_resource_group", 0.98
    return "provider_type_and_literal_name", 0.9


def link_terraform_resource(repository, *, provider: str, resource_uid: str,
                            state_document: Mapping | None = None,
                            resource_types: tuple[str, ...] = ()) -> TerraformLink:
    """Return one unambiguous Terraform owner for a cloud resource."""
    root = Path(repository).resolve(strict=True)
    if not root.is_dir():
        raise TerraformLinkError(f"repository is not a directory: {root}")
    if not provider or not resource_uid:
        raise TerraformLinkError("provider and resource_uid are required")
    if state_document is not None and not isinstance(state_document, Mapping):
        raise TerraformLinkError("Terraform state document must be an object")
    if (not isinstance(resource_types, tuple)
            or any(not isinstance(item, str) or not item for item in resource_types)
            or len(resource_types) != len(set(resource_types))):
        raise TerraformLinkError(
            "resource_types must be a tuple of unique non-empty strings")
    identity = _cloud_identity(provider, resource_uid)
    eligible_state_types = (
        resource_types or tuple(filter(None, (identity.terraform_type,))))
    state_owner = (
        _state_owner(
            state_document, provider=provider, resource_uid=resource_uid,
            resource_types=eligible_state_types)
        if state_document is not None else None
    )
    candidates: list[tuple[_Block, str, float]] = []
    for path in _terraform_files(root):
        for block in _blocks(path):
            if (state_owner and block.resource_type == state_owner[1]
                    and block.resource_name == state_owner[2]):
                matched = ("terraform_state_resource_id", 1.0)
            else:
                matched = _candidate(
                    block, provider=provider, resource_uid=resource_uid,
                    identity=identity, resource_types=resource_types,
                )
            if matched:
                candidates.append((block, *matched))

    if not candidates:
        expected = (", ".join(resource_types)
                    if resource_types else
                    identity.terraform_type or "a literal resource UID")
        raise TerraformLinkNotFound(
            f"no Terraform block links {provider}:{resource_uid}; expected {expected}"
        )
    highest = max(candidate[2] for candidate in candidates)
    winners = [candidate for candidate in candidates if candidate[2] == highest]
    if len(winners) != 1:
        locations = ", ".join(
            f"{block.source_path.relative_to(root)}:{block.start_line}"
            for block, _, _ in winners
        )
        raise AmbiguousTerraformLink(
            f"multiple Terraform blocks match {resource_uid}: {locations}"
        )
    block, strategy, confidence = winners[0]
    relative = block.source_path.relative_to(root).as_posix()
    module = block.source_path.parent.relative_to(root).as_posix()
    return TerraformLink(
        resource_uid=resource_uid,
        source_path=relative,
        module_path="." if module == "." else module,
        resource_type=block.resource_type,
        resource_name=block.resource_name,
        start_line=block.start_line,
        end_line=block.end_line,
        match_strategy=strategy,
        confidence=confidence,
        source_sha256=sha256_file(block.source_path),
        resource_address=state_owner[0] if state_owner else "",
        state_sha256=(sha256_bytes(canonical_json(state_document))
                      if state_document is not None else ""),
    )
