-- Forgotten database backup, left in a publicly web-accessible folder.
-- VULN: CWE-16 / CWE-530 (Exposure of Backup File to an Unauthorized Control Sphere)
CREATE TABLE customers (id INT, full_name VARCHAR(100), email VARCHAR(100), card_last4 VARCHAR(4));
INSERT INTO customers VALUES (1, 'Jane Doe', 'jane.doe@example.com', '4242');
INSERT INTO customers VALUES (2, 'John Smith', 'john.smith@example.com', '1881');
INSERT INTO customers VALUES (3, 'Priya Nair', 'priya.nair@example.com', '5309');
-- END OF BACKUP — fake demo data, not real customers.
