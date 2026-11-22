-- 数字函数恢复功能升级说明
-- 功能ID：5 = 数字函数恢复（高级订阅专用）。
-- 本升级不改表结构，只规范默认订阅功能：
--   默认体验: [1]
--   标准订阅: [1,2,4]
--   高级订阅: [0]，代表全部功能，因此包含功能5。
-- 如果你以后自定义订阅，也可以手动把 5 加入 features_json。

UPDATE subscriptions SET features_json=JSON_ARRAY(1) WHERE sub_id=0;
UPDATE subscriptions SET features_json=JSON_ARRAY(1,2,4) WHERE sub_id=1;
UPDATE subscriptions SET features_json=JSON_ARRAY(0) WHERE sub_id=2;
