-- Generate 8-digit access codes for all users who don't have one yet.
UPDATE users
SET access_code = LPAD(FLOOR(RANDOM() * 100000000)::TEXT, 8, '0')
WHERE access_code IS NULL;

-- Ensure access_code is not null going forward.
ALTER TABLE users ALTER COLUMN access_code SET NOT NULL;
