-- iAPT V190: feature 999 + protected xbhostroot/subscription triggers
USE iapp_saas;

-- Drop only V190 guards first so this migration is safely rerunnable.
DROP TRIGGER IF EXISTS trg_iapt_v190_sub999_bu;
DROP TRIGGER IF EXISTS trg_iapt_v190_sub999_bd;
DROP TRIGGER IF EXISTS trg_iapt_v190_xb_user_bu;
DROP TRIGGER IF EXISTS trg_iapt_v190_xb_user_bd;
DROP TRIGGER IF EXISTS trg_iapt_v190_xb_perm_bi;
DROP TRIGGER IF EXISTS trg_iapt_v190_xb_perm_bu;
DROP TRIGGER IF EXISTS trg_iapt_v190_xb_perm_bd;
DROP TRIGGER IF EXISTS trg_iapt_v190_xb_sub_bi;
DROP TRIGGER IF EXISTS trg_iapt_v190_xb_sub_bu;
DROP TRIGGER IF EXISTS trg_iapt_v190_xb_sub_bd;

INSERT INTO subscriptions(sub_id, sub_name, daily_quota, features_json)
VALUES(999999999, '内部专用订阅', 2147483647, '[999]')
ON DUPLICATE KEY UPDATE
  sub_name=VALUES(sub_name),
  daily_quota=VALUES(daily_quota),
  features_json=VALUES(features_json);

INSERT INTO users(name, username, password_hash, balance, subscription_id,
                  subscription_expire, permission, banned)
SELECT 'xbhostroot', 'xbhostroot',
       'a87e83e3e57212f50141b6ca70c9c939497ba750d524597afc5c19f70a823e28',
       0, 999999999, NULL, 999, 0
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username='xbhostroot');

-- Preserve the existing password hash. Normalize protected status once.
UPDATE users
SET permission=999,
    banned=0,
    subscription_id=999999999,
    subscription_expire=NULL
WHERE username='xbhostroot';

SET @iapt_xb_id := (SELECT id FROM users WHERE username='xbhostroot' LIMIT 1);

DELETE FROM admin_permissions WHERE user_id=@iapt_xb_id;
INSERT IGNORE INTO admin_permissions(user_id, permission_id, granted_by)
VALUES(@iapt_xb_id, 999, @iapt_xb_id);

-- Do not use a temporary stored procedure here. Some upgraded servers can run
-- application SQL while mysql.proc still has the old column layout; any
-- CREATE/DROP PROCEDURE then fails with ERROR 1558. A session-local prepared
-- statement gives the same schema-compatible branch without touching mysql.proc.
SET @iapt_has_dedupe := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema=DATABASE()
    AND table_name='user_subscriptions'
    AND column_name='expire_at_dedupe'
);

DELETE FROM user_subscriptions WHERE user_id=@iapt_xb_id;

SET @iapt_seed_sql := IF(
  @iapt_has_dedupe > 0,
  'INSERT INTO user_subscriptions(user_id, sub_id, expire_at, expire_at_dedupe) VALUES(?, 999999999, NULL, \'1000-01-01 00:00:00\')',
  'INSERT INTO user_subscriptions(user_id, sub_id, expire_at) VALUES(?, 999999999, NULL)'
);
PREPARE iapt_v190_seed_stmt FROM @iapt_seed_sql;
EXECUTE iapt_v190_seed_stmt USING @iapt_xb_id;
DEALLOCATE PREPARE iapt_v190_seed_stmt;
SET @iapt_seed_sql := NULL;
SET @iapt_has_dedupe := NULL;


DELIMITER $$
CREATE TRIGGER trg_iapt_v190_sub999_bu
BEFORE UPDATE ON subscriptions FOR EACH ROW
BEGIN
  IF OLD.sub_id=999999999 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='修改失败';
  END IF;
END$$

CREATE TRIGGER trg_iapt_v190_sub999_bd
BEFORE DELETE ON subscriptions FOR EACH ROW
BEGIN
  IF OLD.sub_id=999999999 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='修改失败';
  END IF;
END$$

CREATE TRIGGER trg_iapt_v190_xb_user_bu
BEFORE UPDATE ON users FOR EACH ROW
BEGIN
  IF OLD.username='xbhostroot' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='修改失败';
  END IF;
END$$

CREATE TRIGGER trg_iapt_v190_xb_user_bd
BEFORE DELETE ON users FOR EACH ROW
BEGIN
  IF OLD.username='xbhostroot' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='修改失败';
  END IF;
END$$

CREATE TRIGGER trg_iapt_v190_xb_perm_bi
BEFORE INSERT ON admin_permissions FOR EACH ROW
BEGIN
  IF EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND username='xbhostroot') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='修改失败';
  END IF;
END$$

CREATE TRIGGER trg_iapt_v190_xb_perm_bu
BEFORE UPDATE ON admin_permissions FOR EACH ROW
BEGIN
  IF EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id AND username='xbhostroot') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='修改失败';
  END IF;
END$$

CREATE TRIGGER trg_iapt_v190_xb_perm_bd
BEFORE DELETE ON admin_permissions FOR EACH ROW
BEGIN
  IF EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id AND username='xbhostroot') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='修改失败';
  END IF;
END$$

CREATE TRIGGER trg_iapt_v190_xb_sub_bi
BEFORE INSERT ON user_subscriptions FOR EACH ROW
BEGIN
  IF EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND username='xbhostroot') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='修改失败';
  END IF;
END$$

CREATE TRIGGER trg_iapt_v190_xb_sub_bu
BEFORE UPDATE ON user_subscriptions FOR EACH ROW
BEGIN
  IF EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id AND username='xbhostroot') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='修改失败';
  END IF;
END$$

CREATE TRIGGER trg_iapt_v190_xb_sub_bd
BEFORE DELETE ON user_subscriptions FOR EACH ROW
BEGIN
  IF EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id AND username='xbhostroot') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='修改失败';
  END IF;
END$$
DELIMITER ;

-- Verification is performed by deployment scripts without outputting the protected record.
