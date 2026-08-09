from elcapitan.hashing import sha256_bytes, sha256_file, canonical_json, sha256_record
EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def test_known_vector(): assert sha256_bytes(b"") == EMPTY
def test_file_matches_bytes(tmp_path):
    p = tmp_path / "a"; p.write_bytes(b'{"x":1}')
    assert sha256_file(p) == sha256_bytes(b'{"x":1}')
def test_canonical_is_key_order_independent():
    assert canonical_json({"b":1,"a":2}) == canonical_json({"a":2,"b":1})
def test_canonical_has_no_whitespace():
    assert canonical_json({"a":1,"b":2}) == b'{"a":1,"b":2}'
def test_record_hash_changes_on_value_change():
    assert sha256_record({"a":1}) != sha256_record({"a":2})
