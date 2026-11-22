-- v16: 允许任务状态 cancelled，避免停止任务时 Data truncated for column status。
ALTER TABLE tasks MODIFY COLUMN status
  ENUM('pending','queued','running','done','failed','cancelled')
  NOT NULL DEFAULT 'queued'
  COMMENT '排队中/处理中/成功/失败/已停止';

-- 新订阅功能：14 = sokey+dexkey 联合枚举。
-- 功能 0 不会通配功能 14，必须显式加入。
-- 示例（请把 123 替换成实际订阅 ID，并保留该订阅原有功能）：
-- UPDATE subscriptions SET features_json='[0,14]' WHERE sub_id=123;
