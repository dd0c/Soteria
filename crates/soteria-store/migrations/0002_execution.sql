-- Milestone 4: execution monitoring (FR-009..FR-013).
-- Extra process fields: who logged in (auid), terminal and session, the
-- path that was executed (the script, when exe is its interpreter), the
-- parent for lineage (FR-012), and the classification's limitations.
ALTER TABLE processes ADD COLUMN auid INTEGER;
ALTER TABLE processes ADD COLUMN session INTEGER;
ALTER TABLE processes ADD COLUMN tty TEXT;
ALTER TABLE processes ADD COLUMN path BLOB;
ALTER TABLE processes ADD COLUMN script BLOB;
ALTER TABLE processes ADD COLUMN parent_exe BLOB;
ALTER TABLE processes ADD COLUMN parent_comm TEXT;
ALTER TABLE processes ADD COLUMN parent_id INTEGER REFERENCES processes(id);
ALTER TABLE processes ADD COLUMN limitations TEXT;
ALTER TABLE processes ADD COLUMN audit_serial INTEGER;
CREATE INDEX processes_classification_ts ON processes(classification, ts);
CREATE INDEX processes_severity_ts ON processes(severity, ts);
