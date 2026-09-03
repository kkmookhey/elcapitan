from pathlib import Path

import pytest

from elcapitan.terraform_linker import (
    AmbiguousTerraformLink, TerraformLinkNotFound, link_terraform_resource,
)


AZURE_ID = (
    "/subscriptions/sub-1/resourceGroups/lab-rg/providers/"
    "Microsoft.Storage/storageAccounts/labassets"
)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_links_an_azure_resource_by_type_name_and_group(tmp_path):
    source = tmp_path / "infra" / "storage.tf"
    write(source, '''
resource "azurerm_storage_account" "assets" {
  name                = "labassets"
  resource_group_name = "lab-rg"
  location            = "westus2"
}
''')
    link = link_terraform_resource(
        tmp_path, provider="azure", resource_uid=AZURE_ID
    )
    assert link.source_path == "infra/storage.tf"
    assert link.module_path == "infra"
    assert link.resource_type == "azurerm_storage_account"
    assert link.resource_name == "assets"
    assert link.match_strategy == "provider_type_name_and_resource_group"
    assert link.confidence == 0.98
    assert link.start_line == 2
    assert link.end_line == 6


def test_exact_resource_uid_match_supports_an_unmapped_resource_type(tmp_path):
    write(tmp_path / "main.tf", f'''
resource "custom_cloud_resource" "example" {{
  cloud_id = "{AZURE_ID}"
}}
''')
    link = link_terraform_resource(
        tmp_path, provider="azure", resource_uid=AZURE_ID
    )
    assert link.match_strategy == "exact_resource_uid"
    assert link.confidence == 1.0


def test_links_an_aws_s3_bucket_by_literal_bucket_name(tmp_path):
    write(tmp_path / "bucket.tf", '''
resource "aws_s3_bucket" "assets" {
  bucket = "training-assets"
}
''')
    link = link_terraform_resource(
        tmp_path, provider="aws", resource_uid="arn:aws:s3:::training-assets"
    )
    assert link.resource_type == "aws_s3_bucket"
    assert link.source_path == "bucket.tf"


def test_links_the_exact_s3_versioning_resource_for_planning(tmp_path):
    write(tmp_path / "bucket.tf", '''
resource "aws_s3_bucket" "assets" {
  bucket = "training-assets"
}

resource "aws_s3_bucket_versioning" "assets" {
  bucket = "training-assets"
  versioning_configuration {
    status = "Disabled"
  }
}
''')
    state = {
        "version": 4,
        "resources": [
            {
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "assets",
                "instances": [{"attributes": {
                    "id": "training-assets", "bucket": "training-assets"}}],
            },
            {
                "mode": "managed",
                "type": "aws_s3_bucket_versioning",
                "name": "assets",
                "instances": [{"attributes": {
                    "id": "training-assets,111122223333",
                    "bucket": "training-assets"}}],
            },
        ],
    }

    link = link_terraform_resource(
        tmp_path, provider="aws",
        resource_uid="arn:aws:s3:::training-assets",
        state_document=state,
        resource_types=("aws_s3_bucket_versioning",),
    )

    assert link.resource_type == "aws_s3_bucket_versioning"
    assert link.resource_address == "aws_s3_bucket_versioning.assets"
    assert link.match_strategy == "terraform_state_resource_id"
    assert len(link.state_sha256) == 64


def test_s3_versioning_linker_requires_an_explicit_supported_type(tmp_path):
    write(tmp_path / "bucket.tf", '''
resource "aws_s3_bucket" "assets" {
  bucket = "training-assets"
}
''')

    with pytest.raises(TerraformLinkNotFound, match="aws_s3_bucket_versioning"):
        link_terraform_resource(
            tmp_path, provider="aws",
            resource_uid="arn:aws:s3:::training-assets",
            resource_types=("aws_s3_bucket_versioning",),
        )


def test_ambiguous_literal_owners_are_rejected(tmp_path):
    block = '''
resource "azurerm_storage_account" "assets" {
  name = "labassets"
}
'''
    write(tmp_path / "a.tf", block)
    write(tmp_path / "module" / "b.tf", block.replace('"assets"', '"copy"'))
    with pytest.raises(AmbiguousTerraformLink, match="a.tf:2.*module/b.tf:2"):
        link_terraform_resource(tmp_path, provider="azure", resource_uid=AZURE_ID)


def test_dynamic_names_are_not_guessed(tmp_path):
    write(tmp_path / "main.tf", '''
resource "azurerm_storage_account" "assets" {
  name = var.storage_account_name
}
''')
    with pytest.raises(TerraformLinkNotFound):
        link_terraform_resource(tmp_path, provider="azure", resource_uid=AZURE_ID)


def test_state_maps_a_computed_name_to_its_source_block(tmp_path):
    write(tmp_path / "storage.tf", '''
resource "azurerm_storage_account" "assets" {
  name = local.generated_storage_name
}
''')
    state = {
        "values": {
            "root_module": {
                "resources": [{
                    "address": "azurerm_storage_account.assets",
                    "type": "azurerm_storage_account",
                    "name": "assets",
                    "values": {"id": AZURE_ID, "name": "labassets"},
                }]
            }
        }
    }
    link = link_terraform_resource(
        tmp_path, provider="azure", resource_uid=AZURE_ID,
        state_document=state,
    )
    assert link.source_path == "storage.tf"
    assert link.match_strategy == "terraform_state_resource_id"
    assert link.resource_address == "azurerm_storage_account.assets"
    assert len(link.state_sha256) == 64


def test_raw_state_maps_a_module_for_each_instance(tmp_path):
    write(tmp_path / "modules" / "storage" / "main.tf", '''
resource "azurerm_storage_account" "assets" {
  name = each.value.name
}
''')
    state = {
        "resources": [{
            "module": "module.storage",
            "mode": "managed",
            "type": "azurerm_storage_account",
            "name": "assets",
            "instances": [{
                "index_key": "blue",
                "attributes": {"id": AZURE_ID},
            }],
        }]
    }
    link = link_terraform_resource(
        tmp_path, provider="azure", resource_uid=AZURE_ID,
        state_document=state,
    )
    assert link.resource_address == (
        'module.storage.azurerm_storage_account.assets["blue"]'
    )
    assert link.source_path == "modules/storage/main.tf"


def test_state_document_must_be_an_object(tmp_path):
    with pytest.raises(ValueError, match="must be an object"):
        link_terraform_resource(
            tmp_path, provider="azure", resource_uid=AZURE_ID,
            state_document=[],
        )


def test_terraform_cache_and_symlinks_are_not_searched(tmp_path):
    source = tmp_path / ".terraform" / "cached.tf"
    write(source, f'resource "x" "y" {{ id = "{AZURE_ID}" }}\n')
    (tmp_path / "linked.tf").symlink_to(source)
    with pytest.raises(TerraformLinkNotFound):
        link_terraform_resource(tmp_path, provider="azure", resource_uid=AZURE_ID)
