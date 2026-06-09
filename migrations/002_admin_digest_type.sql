-- Allow managed users (created by admin) to have no email or password
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- 8-digit numeric access code for code-based login (managed users)
ALTER TABLE users ADD COLUMN access_code text UNIQUE;

-- Admin flag; first registered user becomes admin automatically
ALTER TABLE users ADD COLUMN is_admin boolean NOT NULL DEFAULT false;

-- Digest type: analytical, farming, or company_group
ALTER TABLE digests ADD COLUMN digest_type text NOT NULL DEFAULT 'analytical';
ALTER TABLE digests ADD CONSTRAINT digest_type_check
    CHECK (digest_type IN ('analytical', 'farming', 'company_group'));
