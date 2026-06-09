-- Assign admin to the most recently registered user if no admin exists yet.
-- Covers the case where migration 002 zeroed is_admin for pre-existing users.
UPDATE users
SET is_admin = true
WHERE id = (SELECT id FROM users ORDER BY created_at DESC LIMIT 1)
  AND NOT EXISTS (SELECT 1 FROM users WHERE is_admin = true);
