-- 1. Drop the auto-named foreign key from shares.version_id
DECLARE
    v_name VARCHAR2(128);
BEGIN
    SELECT c.constraint_name
    INTO v_name
    FROM user_constraints c
    JOIN user_cons_columns cc
      ON c.constraint_name = cc.constraint_name
    WHERE c.table_name = 'SHARES'
      AND cc.table_name = 'SHARES'
      AND c.constraint_type = 'R'
      AND cc.column_name = 'VERSION_ID';

    EXECUTE IMMEDIATE
        'ALTER TABLE shares DROP CONSTRAINT ' || v_name;
END;
/

-- 2. Keep the share row even if the version is deleted
ALTER TABLE shares MODIFY (version_id NULL);

ALTER TABLE shares ADD CONSTRAINT fk_shares_version
    FOREIGN KEY (version_id)
    REFERENCES versions(id)
    ON DELETE SET NULL;

-- 3. Snapshot columns
ALTER TABLE shares ADD (
    owner_id NUMBER REFERENCES users(id) ON DELETE CASCADE,
    file_label VARCHAR2(400)
);
