-- 下载额度修复升级 SQL：可重复执行。
-- 作用：补齐任务额度字段，让旧任务在后来有额度时也能追加扣除并下载。
USE iapp_saas;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'daily_quotas' AND COLUMN_NAME = 'extra_quota');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE daily_quotas ADD COLUMN extra_quota INT NOT NULL DEFAULT 0 COMMENT ''用户主动余额兑换所得额度''', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'apk_sha256');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN apk_sha256 CHAR(64) NULL', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'options_hash');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN options_hash CHAR(64) NULL', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'cached_from_task_id');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN cached_from_task_id BIGINT NULL', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'resource_quota_cost');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN resource_quota_cost INT NOT NULL DEFAULT 0 COMMENT ''提交任务资源额度消耗''', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'resource_quota_deducted');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN resource_quota_deducted TINYINT NOT NULL DEFAULT 0', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'resource_quota_note');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN resource_quota_note TEXT NULL', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'estimated_quota_cost');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN estimated_quota_cost INT NOT NULL DEFAULT 0', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'quota_limit');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN quota_limit INT NOT NULL DEFAULT 0', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'actual_quota_cost');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN actual_quota_cost INT NOT NULL DEFAULT 0', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'decrypt_quota_deducted');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN decrypt_quota_deducted INT NOT NULL DEFAULT 0', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'downloadable_file_count');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN downloadable_file_count INT NOT NULL DEFAULT 0', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'downloadable_bytes');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN downloadable_bytes BIGINT NOT NULL DEFAULT 0', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists := (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'quota_note');
SET @sql := IF(@col_exists = 0, 'ALTER TABLE tasks ADD COLUMN quota_note TEXT NULL', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 如果旧库 tasks.status 还是 pending/running/done/failed，先临时兼容两种枚举，再把 pending 数据改成 queued。
ALTER TABLE tasks MODIFY COLUMN status ENUM('pending','queued','running','done','failed') NOT NULL DEFAULT 'queued' COMMENT '排队中/处理中/成功/失败';
UPDATE tasks SET status='queued' WHERE status='pending';
ALTER TABLE tasks MODIFY COLUMN status ENUM('queued','running','done','failed') NOT NULL DEFAULT 'queued' COMMENT '排队中/处理中/成功/失败';
