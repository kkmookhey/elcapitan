import pytest

from elcapitan.product_records import (
    DuplicateProductRecord, ProductRecord, ProductRecordNotFound,
    SqliteProductRecordStore,
)


def record(record_id="VAL-001", record_type="ValidationResult.v1"):
    return ProductRecord(
        record_id=record_id, case_id="CASE-001", record_type=record_type,
        schema_version=1, created_at="2026-08-25T12:00:00Z",
        body={"status": "confirmed"}, evidence_ids=("EVD-001",))


def test_record_is_immutable_and_survives_store_restart(tmp_path):
    path = tmp_path / "product.db"
    store = SqliteProductRecordStore(path)
    store.put(record())
    assert SqliteProductRecordStore(path).get("VAL-001") == record()


def test_record_ids_are_append_only(tmp_path):
    store = SqliteProductRecordStore(tmp_path / "product.db")
    store.put(record())
    with pytest.raises(DuplicateProductRecord):
        store.put(record())


def test_records_can_be_filtered_by_case_and_type(tmp_path):
    store = SqliteProductRecordStore(tmp_path / "product.db")
    store.put(record())
    store.put(record("SRE-001", "SREReview.v1"))
    assert store.list_for_case("CASE-001", record_type="ValidationResult.v1") == (
        record(),)


def test_missing_record_is_named(tmp_path):
    store = SqliteProductRecordStore(tmp_path / "product.db")
    with pytest.raises(ProductRecordNotFound):
        store.get("VAL-999")


def test_nested_record_body_is_detached_from_runtime_mutation():
    body = {"findings": [{"status": "confirmed"}]}
    product = ProductRecord(
        record_id="VAL-001", case_id="CASE-001", record_type="ValidationResult.v1",
        schema_version=1, created_at="2026-08-25T12:00:00Z", body=body)
    body["findings"][0]["status"] = "tampered"
    assert product.body["findings"][0]["status"] == "confirmed"
