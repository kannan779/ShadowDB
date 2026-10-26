import hashlib
import json
from datetime import datetime, timezone
from database import query, transaction

def canonical_hash(employee_code, full_name, department, email, salary, status):
    value = '|'.join(map(str, [employee_code, full_name, department, email, salary, status]))
    return hashlib.sha256(value.encode()).hexdigest()

def list_employees():
    return query('SELECT * FROM employees ORDER BY employee_id DESC')

def list_audit(limit=100):
    return query('SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT %s', (limit,))

def list_versions(employee_id):
    return query('SELECT * FROM employee_versions WHERE employee_id=%s ORDER BY version_no DESC', (employee_id,))

def add_employee(data, actor):
    row_hash = canonical_hash(data['employee_code'], data['full_name'], data['department'], data['email'], data['salary'], data['status'])
    with transaction() as conn:
        cur = conn.cursor()
        cur.execute('SET @shadowdb_actor = %s', (actor,))
        cur.execute('''INSERT INTO employees (employee_code,full_name,department,email,salary,status,row_hash,updated_by)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (*[data[k] for k in ('employee_code','full_name','department','email','salary','status')], row_hash, actor))
        audit_id = latest_audit_id(conn, cur.lastrowid, actor)
        evaluate_alerts(conn, actor, audit_id)

def update_employee(employee_id, data, actor):
    row_hash = canonical_hash(data['employee_code'], data['full_name'], data['department'], data['email'], data['salary'], data['status'])
    with transaction() as conn:
        cur = conn.cursor()
        cur.execute('SET @shadowdb_actor = %s', (actor,))
        cur.execute('''UPDATE employees SET employee_code=%s,full_name=%s,department=%s,email=%s,salary=%s,
                       status=%s,row_hash=%s,version_no=version_no+1,updated_by=%s WHERE employee_id=%s''',
                    (*[data[k] for k in ('employee_code','full_name','department','email','salary','status')], row_hash, actor, employee_id))
        if cur.rowcount != 1:
            raise ValueError('Employee was not found.')
        evaluate_alerts(conn, actor, latest_audit_id(conn, employee_id, actor))

def delete_employee(employee_id, actor):
    with transaction() as conn:
        cur = conn.cursor()
        cur.execute('SET @shadowdb_actor = %s', (actor,))
        cur.execute('DELETE FROM employees WHERE employee_id=%s', (employee_id,))
        if cur.rowcount != 1:
            raise ValueError('Employee was not found.')
        evaluate_alerts(conn, actor, latest_audit_id(conn, employee_id, actor))

def restore_version(employee_id, version_no, actor):
    rows = query('SELECT * FROM employee_versions WHERE employee_id=%s AND version_no=%s', (employee_id, version_no))
    if not rows:
        raise ValueError('Version was not found.')
    row = rows[0]
    update_employee(employee_id, row, actor)

def restore_deleted(audit_id, actor):
    rows = query("SELECT old_snapshot FROM audit_log WHERE audit_id=%s AND operation='DELETE'", (audit_id,))
    if not rows:
        raise ValueError('A delete audit event was not found.')
    snapshot = rows[0]['old_snapshot']
    if isinstance(snapshot, str):
        snapshot = json.loads(snapshot)
    data = {key: snapshot[key] for key in ('employee_code', 'full_name', 'department', 'email', 'salary', 'status')}
    add_employee(data, actor)

def verify_chain():
    rows = query('SELECT audit_id,operation,entity_id,actor,previous_hash,event_hash,new_snapshot,old_snapshot FROM audit_log ORDER BY audit_id')
    previous = '0' * 64
    result = []
    for row in rows:
        snapshot = row['new_snapshot'] or row['old_snapshot']
        if isinstance(snapshot, str):
            snapshot = json.loads(snapshot)
        expected = hashlib.sha256(f"{previous}{row['operation']}{row['entity_id']}{snapshot.get('row_hash')}{row['actor']}".encode()).hexdigest()
        valid = row['previous_hash'] == previous and row['event_hash'] == expected
        result.append({'audit_id': row['audit_id'], 'valid': valid, 'expected': expected, 'actual': row['event_hash']})
        previous = row['event_hash']
    return result

def evaluate_alerts(conn, actor, audit_id):
    cur = conn.cursor()
    cur.execute("""SELECT COUNT(*) FROM audit_log WHERE actor=%s AND operation='DELETE' AND event_time >= NOW() - INTERVAL 10 MINUTE""", (actor,))
    deletes = cur.fetchone()[0]
    if deletes >= 3:
        cur.execute("INSERT INTO security_alerts (alert_type,severity,actor,description,related_audit_id) VALUES (%s,%s,%s,%s,%s)",
                    ('DELETE_BURST','HIGH',actor,f'{deletes} deletes by {actor} in the last 10 minutes',audit_id))
    hour = datetime.now(timezone.utc).hour
    if hour < 5 or hour >= 20:
        cur.execute("INSERT INTO security_alerts (alert_type,severity,actor,description,related_audit_id) VALUES (%s,%s,%s,%s,%s)",
                    ('AFTER_HOURS','MEDIUM',actor,'Database change observed outside the normal operating window',audit_id))

def latest_audit_id(conn, entity_id, actor):
    cur = conn.cursor()
    cur.execute("""SELECT audit_id FROM audit_log
                   WHERE entity_name='employees' AND entity_id=%s AND actor=%s
                   ORDER BY audit_id DESC LIMIT 1""", (entity_id, actor))
    row = cur.fetchone()
    return row[0] if row else None
