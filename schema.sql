CREATE DATABASE IF NOT EXISTS shadowdb CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE shadowdb;

DROP TRIGGER IF EXISTS trg_employee_ai;
DROP TRIGGER IF EXISTS trg_employee_au;
DROP TRIGGER IF EXISTS trg_employee_ad;
DROP PROCEDURE IF EXISTS verify_audit_chain;

CREATE TABLE IF NOT EXISTS employees (
    employee_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    employee_code VARCHAR(30) NOT NULL UNIQUE,
    full_name VARCHAR(120) NOT NULL,
    department VARCHAR(80) NOT NULL,
    email VARCHAR(160) NOT NULL UNIQUE,
    salary DECIMAL(12,2) NOT NULL CHECK (salary >= 0),
    status ENUM('ACTIVE','SUSPENDED','TERMINATED') NOT NULL DEFAULT 'ACTIVE',
    row_hash CHAR(64) NOT NULL,
    version_no INT UNSIGNED NOT NULL DEFAULT 1,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    updated_by VARCHAR(120) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS employee_versions (
    version_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    employee_id BIGINT UNSIGNED NOT NULL,
    version_no INT UNSIGNED NOT NULL,
    employee_code VARCHAR(30) NOT NULL,
    full_name VARCHAR(120) NOT NULL,
    department VARCHAR(80) NOT NULL,
    email VARCHAR(160) NOT NULL,
    salary DECIMAL(12,2) NOT NULL,
    status VARCHAR(20) NOT NULL,
    row_hash CHAR(64) NOT NULL,
    captured_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    captured_by VARCHAR(120) NOT NULL,
    UNIQUE KEY uq_employee_version (employee_id, version_no),
    INDEX ix_versions_employee_time (employee_id, captured_at)
    -- Deliberately no FK here: historical evidence must survive a current-row delete.
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    entity_name VARCHAR(60) NOT NULL,
    entity_id BIGINT UNSIGNED NOT NULL,
    operation ENUM('INSERT','UPDATE','DELETE') NOT NULL,
    actor VARCHAR(120) NOT NULL,
    event_time TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    old_snapshot JSON NULL,
    new_snapshot JSON NULL,
    previous_hash CHAR(64) NOT NULL,
    event_hash CHAR(64) NOT NULL,
    INDEX ix_audit_entity_time (entity_name, entity_id, event_time),
    INDEX ix_audit_actor_time (actor, event_time),
    INDEX ix_audit_operation_time (operation, event_time)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(60) NOT NULL,
    severity ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
    actor VARCHAR(120) NOT NULL,
    description VARCHAR(500) NOT NULL,
    related_audit_id BIGINT UNSIGNED NULL,
    detected_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    acknowledged TINYINT(1) NOT NULL DEFAULT 0,
    INDEX ix_alerts_open_time (acknowledged, detected_at),
    INDEX ix_alerts_actor_time (actor, detected_at),
    CONSTRAINT fk_alert_audit FOREIGN KEY (related_audit_id) REFERENCES audit_log(audit_id) ON DELETE SET NULL
) ENGINE=InnoDB;

DELIMITER $$
CREATE TRIGGER trg_employee_ai AFTER INSERT ON employees FOR EACH ROW
BEGIN
    INSERT INTO employee_versions (employee_id, version_no, employee_code, full_name, department, email, salary, status, row_hash, captured_by)
    VALUES (NEW.employee_id, NEW.version_no, NEW.employee_code, NEW.full_name, NEW.department, NEW.email, NEW.salary, NEW.status, NEW.row_hash, NEW.updated_by);
    INSERT INTO audit_log (entity_name, entity_id, operation, actor, old_snapshot, new_snapshot, previous_hash, event_hash)
    SELECT 'employees', NEW.employee_id, 'INSERT', COALESCE(@shadowdb_actor, NEW.updated_by), NULL,
           JSON_OBJECT('employee_code',NEW.employee_code,'full_name',NEW.full_name,'department',NEW.department,'email',NEW.email,'salary',NEW.salary,'status',NEW.status,'row_hash',NEW.row_hash),
           COALESCE((SELECT event_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1), REPEAT('0',64)),
           SHA2(CONCAT(COALESCE((SELECT event_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1), REPEAT('0',64)), 'INSERT', NEW.employee_id, NEW.row_hash, COALESCE(@shadowdb_actor, NEW.updated_by)), 256);
END$$
CREATE TRIGGER trg_employee_au AFTER UPDATE ON employees FOR EACH ROW
BEGIN
    INSERT INTO employee_versions (employee_id, version_no, employee_code, full_name, department, email, salary, status, row_hash, captured_by)
    VALUES (NEW.employee_id, NEW.version_no, NEW.employee_code, NEW.full_name, NEW.department, NEW.email, NEW.salary, NEW.status, NEW.row_hash, NEW.updated_by);
    INSERT INTO audit_log (entity_name, entity_id, operation, actor, old_snapshot, new_snapshot, previous_hash, event_hash)
    SELECT 'employees', NEW.employee_id, 'UPDATE', COALESCE(@shadowdb_actor, NEW.updated_by),
           JSON_OBJECT('employee_code',OLD.employee_code,'full_name',OLD.full_name,'department',OLD.department,'email',OLD.email,'salary',OLD.salary,'status',OLD.status,'row_hash',OLD.row_hash),
           JSON_OBJECT('employee_code',NEW.employee_code,'full_name',NEW.full_name,'department',NEW.department,'email',NEW.email,'salary',NEW.salary,'status',NEW.status,'row_hash',NEW.row_hash),
           COALESCE((SELECT event_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1), REPEAT('0',64)),
           SHA2(CONCAT(COALESCE((SELECT event_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1), REPEAT('0',64)), 'UPDATE', NEW.employee_id, NEW.row_hash, COALESCE(@shadowdb_actor, NEW.updated_by)), 256);
END$$
CREATE TRIGGER trg_employee_ad AFTER DELETE ON employees FOR EACH ROW
BEGIN
    INSERT INTO audit_log (entity_name, entity_id, operation, actor, old_snapshot, new_snapshot, previous_hash, event_hash)
    SELECT 'employees', OLD.employee_id, 'DELETE', COALESCE(@shadowdb_actor, OLD.updated_by),
           JSON_OBJECT('employee_code',OLD.employee_code,'full_name',OLD.full_name,'department',OLD.department,'email',OLD.email,'salary',OLD.salary,'status',OLD.status,'row_hash',OLD.row_hash), NULL,
           COALESCE((SELECT event_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1), REPEAT('0',64)),
           SHA2(CONCAT(COALESCE((SELECT event_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1), REPEAT('0',64)), 'DELETE', OLD.employee_id, OLD.row_hash, COALESCE(@shadowdb_actor, OLD.updated_by)), 256);
END$$
CREATE PROCEDURE verify_audit_chain()
BEGIN
    SELECT audit_id, event_time, operation, actor,
           event_hash = SHA2(CONCAT(previous_hash, operation, entity_id,
               JSON_UNQUOTE(JSON_EXTRACT(COALESCE(new_snapshot, old_snapshot), '$.row_hash')), actor), 256) AS is_valid
    FROM audit_log ORDER BY audit_id;
END$$
DELIMITER ;

CREATE USER IF NOT EXISTS 'shadow_app'@'localhost' IDENTIFIED BY 'change-me';
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON shadowdb.* TO 'shadow_app'@'localhost';
FLUSH PRIVILEGES;
