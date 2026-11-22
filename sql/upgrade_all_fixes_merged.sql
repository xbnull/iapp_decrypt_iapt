-- iAPT merged server fixes migration
CREATE TABLE IF NOT EXISTS decrypt_whitelist (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  package_name VARCHAR(255) NOT NULL,
  code_hash VARCHAR(128) NOT NULL,
  expire_at DATETIME NULL,
  note VARCHAR(255) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_pkg_hash(package_name, code_hash),
  KEY idx_expire(expire_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO admin_permission_defs(permission_id,name,description) VALUES
(602,'白名单管理','添加、删除、修改保护白名单'),
(603,'任务操作','删除任务、下载任务源码'),
(604,'清空上传文件','一键清空 storage/uploads 上传文件'),
(605,'清空任务文件','一键清空任务输出文件和临时 ZIP'),
(606,'清空任务记录','只清空任务/下载/缓存数据库记录并重置任务ID，不删除文件');

-- 以下 ALTER 在旧 MySQL 不支持 IF NOT EXISTS 时可忽略，服务端启动会自动按 information_schema 补列。
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS decrypt_version VARCHAR(8) DEFAULT 'v3';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS code_hash VARCHAR(128) NULL;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS icon_path VARCHAR(1024) NULL;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS download_count INT DEFAULT 0;
