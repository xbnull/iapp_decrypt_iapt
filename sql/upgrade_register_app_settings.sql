-- 注册/验证码/公告/更新/软件开关/卡密交互管理升级
CREATE TABLE IF NOT EXISTS app_settings (
  setting_key VARCHAR(64) PRIMARY KEY,
  setting_value TEXT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO app_settings(setting_key, setting_value) VALUES
  ('register_enabled','0'),
  ('app_enabled','1'),
  ('app_closed_message','软件维护中，请稍后再试。'),
  ('announcement_enabled','0'),
  ('announcement_title','公告'),
  ('announcement_text',''),
  ('update_version_code','1'),
  ('update_version_name','1.0'),
  ('update_url',''),
  ('update_log',''),
  ('force_update','0')
ON DUPLICATE KEY UPDATE setting_key=VALUES(setting_key);

CREATE TABLE IF NOT EXISTS captcha_challenges (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  captcha_id VARCHAR(64) NOT NULL UNIQUE,
  code VARCHAR(16) NOT NULL,
  ip VARCHAR(64) NOT NULL,
  used TINYINT NOT NULL DEFAULT 0,
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_captcha_ip(ip),
  INDEX idx_captcha_exp(expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS register_events (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  ip VARCHAR(64) NOT NULL,
  username VARCHAR(64) NOT NULL,
  user_id BIGINT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_reg_ip_created(ip, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET @col_exists := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='cards' AND COLUMN_NAME='disabled');
SET @sql := IF(@col_exists=0, 'ALTER TABLE cards ADD COLUMN disabled TINYINT NOT NULL DEFAULT 0 AFTER used_at', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

INSERT INTO permission_defs(permission_id, permission_name, description)
VALUES
  (203, '操作卡密', '作废、恢复、清除使用记录或删除卡密'),
  (501, '注册开关', '开启或关闭用户自助注册'),
  (502, '公告管理', '设置客户端公告内容'),
  (503, '更新发布', '发布版本更新和强制更新'),
  (504, '软件开关', '开启或关闭客户端进入')
ON DUPLICATE KEY UPDATE permission_name=VALUES(permission_name), description=VALUES(description);

INSERT IGNORE INTO admin_permissions(user_id, permission_id, granted_by)
SELECT u.id, p.permission_id, u.id
FROM users u JOIN permission_defs p
WHERE u.username='admin';

DELETE FROM captcha_challenges WHERE expires_at < DATE_SUB(NOW(), INTERVAL 1 DAY);
