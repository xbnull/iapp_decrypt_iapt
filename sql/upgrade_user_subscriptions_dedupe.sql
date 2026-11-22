-- iAPT user_subscriptions exact-dedup migration
-- Uniqueness: (user_id, sub_id, expire_at), with NULL treated as one permanent-expiry value.

START TRANSACTION;

DELETE newer
FROM user_subscriptions AS newer
JOIN user_subscriptions AS older
  ON newer.id > older.id
 AND newer.user_id = older.user_id
 AND newer.sub_id = older.sub_id
 AND newer.expire_at <=> older.expire_at;

COMMIT;

SET @has_col := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE()
    AND TABLE_NAME='user_subscriptions'
    AND COLUMN_NAME='expire_at_dedupe'
);
SET @sql := IF(
  @has_col = 0,
  "ALTER TABLE user_subscriptions ADD COLUMN expire_at_dedupe DATETIME NOT NULL DEFAULT '1000-01-01 00:00:00'",
  "SELECT 'expire_at_dedupe already exists'"
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Clean again in case a legacy writer inserted a duplicate during the ALTER.
DELETE newer
FROM user_subscriptions AS newer
JOIN user_subscriptions AS older
  ON newer.id > older.id
 AND newer.user_id = older.user_id
 AND newer.sub_id = older.sub_id
 AND newer.expire_at <=> older.expire_at;

SET @has_idx := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA=DATABASE()
    AND TABLE_NAME='user_subscriptions'
    AND INDEX_NAME='uk_us_user_sub_expire'
);
SET @sql := IF(
  @has_idx = 0,
  "ALTER TABLE user_subscriptions ADD UNIQUE KEY uk_us_user_sub_expire (user_id, sub_id, expire_at_dedupe)",
  "SELECT 'uk_us_user_sub_expire already exists'"
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
