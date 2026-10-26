USE shadowdb;
INSERT INTO employees (employee_code, full_name, department, email, salary, status, row_hash, updated_by)
VALUES
('EMP-1001','Aarav Mehta','Engineering','aarav@example.com',85000,'ACTIVE',SHA2('EMP-1001|Aarav Mehta|Engineering|aarav@example.com|85000|ACTIVE',256),'seed@shadowdb.local'),
('EMP-1002','Isha Nair','Finance','isha@example.com',72000,'ACTIVE',SHA2('EMP-1002|Isha Nair|Finance|isha@example.com|72000|ACTIVE',256),'seed@shadowdb.local');
