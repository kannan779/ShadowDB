# ShadowDB

**Tamper-evident database auditing and insider-threat detection**

ShadowDB is a resume-quality DBMS project for demonstrating how a security-sensitive application can preserve evidence when records are inserted, changed, or deleted. It uses MySQL triggers for immutable-style audit/version capture and Python + Streamlit for the operator console.

## Implemented technical novelties

1. **Database-native audit trail** — `AFTER INSERT/UPDATE/DELETE` triggers record the actor, operation, row snapshot, and timestamp.
2. **Hash-chained evidence** — every audit event stores `previous_hash` and `event_hash`; a verification query recomputes the chain and detects tampering or deletion.
3. **Version history and recovery** — old row states are preserved in `employee_versions`, and an authorized restore is written as a new auditable update.
4. **Transactional security operations** — business changes, audit capture, and alert evaluation run inside an explicit transaction with rollback on failure.
5. **Suspicious-activity detection** — configurable rules flag burst deletes, repeated changes by one actor, and after-hours activity; indexed queries keep the dashboard responsive.

## Architecture

```text
Streamlit console
      |
Python service layer (validation, transactions, alerts, verification)
      |
MySQL 8 (constraints, indexes, triggers, version history, audit chain)
```

## Quick start

### 1. Create the database

```sql
SOURCE schema.sql;
SOURCE seed.sql;
```

The schema creates a database named `shadowdb` and a least-privilege demo user. Change the password before using this outside a classroom demo.

### 2. Configure Python

```powershell
py -m venv .venv
\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `MYSQL_PASSWORD` in `.env`, then run:

```powershell
streamlit run app.py
```

### 3. Demo script for class

1. Add an employee as `admin@shadowdb.local`.
2. Update the salary as `hr@shadowdb.local`.
3. Delete an employee as `admin@shadowdb.local`.
4. Open **Audit Explorer** and show the old/new snapshots.
5. Open **Integrity Check** and show a valid hash chain.
6. Run the **Suspicious Activity** view and explain the generated alert.
7. Restore a deleted employee from its delete event; point out that restoration creates a new insert instead of erasing evidence.

## DBMS concepts demonstrated

- 3NF-style separation of current rows, versions, audit events, and alerts
- primary/foreign keys, unique constraints, check constraints, and indexes
- triggers and stored procedures
- explicit transactions and rollback
- temporal/versioned data
- SHA-256 integrity verification
- least-privilege database account

## Project layout

```text
shadowdb/
├── app.py              # Streamlit dashboard
├── database.py         # connection and transaction helpers
├── security.py         # service layer and integrity/alert logic
├── schema.sql          # MySQL schema, triggers, indexes, procedures
├── seed.sql            # safe demo data
├── tests/test_security.py
├── requirements.txt
├── .env.example
└── README.md
```

## Security note

The audit table is tamper-evident, not magically immutable: a MySQL administrator can still change it. In a production design, revoke write access from application users, ship the chain to append-only object storage, and verify it independently.
