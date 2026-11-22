-- iApp 解密 SaaS 数据库结构（MySQL 5.7+/8.0，宝塔 phpMyAdmin 可直接导入）
CREATE DATABASE IF NOT EXISTS iapp_saas DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE iapp_saas;

CREATE TABLE IF NOT EXISTS subscriptions (
  sub_id INT PRIMARY KEY,
  sub_name VARCHAR(64) NOT NULL,
  daily_quota INT NOT NULL DEFAULT 50,
  features_json JSON NULL COMMENT '支持功能ID，如 [1,2,4]；5=数字函数恢复(高级)；[0] 代表全部功能',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO subscriptions(sub_id, sub_name, daily_quota, features_json)
VALUES
  (0, '默认体验', 50, JSON_ARRAY(1)),
  (1, '标准订阅', 300, JSON_ARRAY(1,2,4)),
  (2, '高级订阅', 1000, JSON_ARRAY(0))
ON DUPLICATE KEY UPDATE sub_name=VALUES(sub_name), daily_quota=VALUES(daily_quota), features_json=VALUES(features_json);

CREATE TABLE IF NOT EXISTS users (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(64) NOT NULL,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(128) NOT NULL,
  balance INT NOT NULL DEFAULT 0 COMMENT '余额，1余额可兑换10额度',
  subscription_id INT NOT NULL DEFAULT 0,
  subscription_expire DATETIME NULL,
  permission INT NOT NULL DEFAULT 0 COMMENT '0普通用户 1管理员 9超级管理员；细分权限见 admin_permissions',
  banned TINYINT NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user_sub(subscription_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;



CREATE TABLE IF NOT EXISTS permission_defs (
  permission_id INT PRIMARY KEY,
  permission_name VARCHAR(64) NOT NULL,
  description VARCHAR(255) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO permission_defs(permission_id, permission_name, description)
VALUES
  (100, '进入后台', '允许进入后台页面'),
  (101, '查看用户列表', '查看用户、余额、订阅、封禁状态'),
  (102, '创建普通用户', '创建普通用户账号；创建管理员仍需要超级管理员'),
  (103, '修改余额', '修改用户余额'),
  (104, '封禁账号', '封禁或解封用户'),
  (105, '修改订阅', '给用户增加或修改订阅'),
  (201, '生成卡密', '生成余额卡或订阅卡'),
  (202, '查看卡密', '查看卡密使用情况'),
  (301, '管理订阅类型', '新增/修改订阅类型和日额度'),
  (401, '查看全部任务', '查看全站任务；普通用户只能看自己的任务'),
  (602, '白名单管理', '添加、删除、修改保护白名单'),
  (603, '任务操作', '删除任务、下载任务源码'),
  (604, '清空上传文件', '一键清空 storage/uploads 上传文件'),
  (605, '清空任务文件', '一键清空任务输出文件和临时 ZIP'),
  (606, '清空任务记录', '只清空任务/下载/缓存数据库记录并重置任务ID，不删除文件'),
  (999, '超级管理员', '拥有全部权限，可创建/编辑其他管理员账号和权限')
ON DUPLICATE KEY UPDATE permission_name=VALUES(permission_name), description=VALUES(description);

CREATE TABLE IF NOT EXISTS admin_permissions (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  permission_id INT NOT NULL,
  granted_by BIGINT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_admin_perm(user_id, permission_id),
  INDEX idx_admin_perm_user(user_id),
  INDEX idx_admin_perm_perm(permission_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_subscriptions (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  sub_id INT NOT NULL,
  expire_at DATETIME NULL,
  expire_at_dedupe DATETIME NOT NULL DEFAULT '1000-01-01 00:00:00',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_us_user_sub_expire(user_id, sub_id, expire_at_dedupe),
  INDEX idx_us_user(user_id),
  INDEX idx_us_sub(sub_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS cards (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  code VARCHAR(64) NOT NULL UNIQUE,
  type ENUM('subscription','balance') NOT NULL,
  sub_id INT NULL,
  amount INT NOT NULL DEFAULT 0 COMMENT '余额卡时为余额数量；订阅卡时为天数，默认30',
  used_by BIGINT NULL,
  used_at DATETIME NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_cards_code(code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sessions (
  token CHAR(64) PRIMARY KEY,
  user_id BIGINT NOT NULL,
  expire_at DATETIME NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_sessions_user(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS daily_quotas (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  quota_date DATE NOT NULL,
  feature_id INT NOT NULL DEFAULT 1,
  total_quota INT NOT NULL DEFAULT 0,
  used_quota INT NOT NULL DEFAULT 0,
  UNIQUE KEY uk_daily(user_id, quota_date, feature_id),
  INDEX idx_daily_user(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tasks (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  task_no CHAR(32) NOT NULL UNIQUE,
  user_id BIGINT NOT NULL,
  apk_name VARCHAR(255) NOT NULL,
  app_name VARCHAR(128) NULL,
  package_name VARCHAR(128) NULL,
  version_name VARCHAR(64) NULL,
  version_code VARCHAR(64) NULL,
  status ENUM('pending','running','done','failed') NOT NULL DEFAULT 'pending',
  feature_id INT NOT NULL DEFAULT 1,
  options_json JSON NULL,
  error_text TEXT NULL,
  total_ms DOUBLE NULL,
  file_count INT NOT NULL DEFAULT 0,
  total_bytes BIGINT NOT NULL DEFAULT 0,
  out_dir VARCHAR(512) NULL,
  log_path VARCHAR(512) NULL,
  apk_sha256 CHAR(64) NULL,
  options_hash CHAR(64) NULL,
  cached_from_task_id BIGINT NULL,
  resource_quota_cost INT NOT NULL DEFAULT 0 COMMENT '提交任务资源额度消耗',
  resource_quota_deducted TINYINT NOT NULL DEFAULT 0,
  resource_quota_note TEXT NULL,
  estimated_quota_cost INT NOT NULL DEFAULT 0,
  quota_limit INT NOT NULL DEFAULT 0,
  actual_quota_cost INT NOT NULL DEFAULT 0,
  decrypt_quota_deducted INT NOT NULL DEFAULT 0,
  downloadable_file_count INT NOT NULL DEFAULT 0,
  downloadable_bytes BIGINT NOT NULL DEFAULT 0,
  quota_note TEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_task_user(user_id),
  INDEX idx_task_status(status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS task_files (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  task_id BIGINT NOT NULL,
  rel_path VARCHAR(512) NOT NULL,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_tf_task(task_id),
  INDEX idx_tf_name(rel_path)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS downloads (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  task_id BIGINT NOT NULL,
  quota_cost INT NOT NULL DEFAULT 0,
  zip_path VARCHAR(512) NOT NULL,
  file_count INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_dl_user(user_id),
  INDEX idx_dl_task(task_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS admin_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  admin_id BIGINT NOT NULL,
  action VARCHAR(128) NOT NULL,
  payload_json JSON NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 默认管理员：admin / admin123456；首次部署后请立即修改密码
-- password_hash = sha256('admin123456')
INSERT INTO users(name, username, password_hash, balance, subscription_id, subscription_expire, permission)
VALUES('超级管理员','admin','240be518fabd2724a5d35f71a322d7cc2865bc4f78d3ddc05ec544c35b9a3fa2',0,2,DATE_ADD(NOW(), INTERVAL 365 DAY),9)
ON DUPLICATE KEY UPDATE username=username;


-- 给默认 admin 授予全部后台权限。普通管理员请在后台由超级管理员创建/分配。
INSERT IGNORE INTO admin_permissions(user_id, permission_id, granted_by)
SELECT u.id, p.permission_id, u.id
FROM users u JOIN permission_defs p
WHERE u.username='admin';
