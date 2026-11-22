-- 修正后台权限模型：超级管理员按 permission_id=999 判断，users.permission 只保留 0/1。
CREATE TABLE IF NOT EXISTS permission_defs (
  permission_id INT PRIMARY KEY,
  permission_name VARCHAR(64) NOT NULL,
  description VARCHAR(255) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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

INSERT INTO permission_defs(permission_id, permission_name, description) VALUES
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

-- 兼容老数据：过去 users.permission>=9 表示超级管理员，现在迁移为 999 权限。
INSERT IGNORE INTO admin_permissions(user_id, permission_id, granted_by)
SELECT id, 999, id FROM users WHERE permission >= 9;

-- 默认 admin 保底给全权限，避免升级后锁在后台外。
INSERT IGNORE INTO admin_permissions(user_id, permission_id, granted_by)
SELECT u.id, p.permission_id, u.id FROM users u JOIN permission_defs p WHERE u.username='admin';

-- 有后台细分权限的用户，users.permission 保持 1；普通用户保持 0。
UPDATE users SET permission=1 WHERE id IN (SELECT DISTINCT user_id FROM admin_permissions);
UPDATE users SET permission=1 WHERE permission >= 9;
UPDATE users SET permission=0 WHERE permission < 0;
