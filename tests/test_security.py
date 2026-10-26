from security import canonical_hash

def test_canonical_hash_is_stable():
    first = canonical_hash('EMP-1','A','IT','a@example.com',50000,'ACTIVE')
    second = canonical_hash('EMP-1','A','IT','a@example.com',50000,'ACTIVE')
    assert first == second
    assert len(first) == 64

def test_canonical_hash_changes_when_data_changes():
    first = canonical_hash('EMP-1','A','IT','a@example.com',50000,'ACTIVE')
    changed = canonical_hash('EMP-1','A','IT','a@example.com',50001,'ACTIVE')
    assert first != changed
