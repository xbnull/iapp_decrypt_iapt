-- iAPT V191.3: database trigger is defense-in-depth only.
-- No stored FUNCTION is used, avoiding mysql.proc version mismatch failures.
USE iapp_saas;

DROP TRIGGER IF EXISTS trg_iapt_v191_tasks_bi;
DROP TRIGGER IF EXISTS trg_iapt_v191_tasks_bu;
DROP TRIGGER IF EXISTS trg_iapt_v1912_tasks_bi;
DROP TRIGGER IF EXISTS trg_iapt_v1912_tasks_bu;

DELIMITER $$
CREATE TRIGGER trg_iapt_v1912_tasks_bi
BEFORE INSERT ON tasks
FOR EACH ROW
BEGIN
    DECLARE v_user_ok INT DEFAULT 0;
    DECLARE v_grants INT DEFAULT 0;
    DECLARE v_feature INT DEFAULT 1;

    SET v_feature = IFNULL(NULLIF(NEW.feature_id,0),1);

    SELECT COUNT(*) INTO v_user_ok
      FROM users u
     WHERE u.id=NEW.user_id AND COALESCE(u.banned,0)=0;

    SELECT COUNT(*) INTO v_grants
      FROM (
            SELECT s.features_json
              FROM user_subscriptions us
              JOIN subscriptions s ON s.sub_id=us.sub_id
             WHERE us.user_id=NEW.user_id
               AND (us.expire_at IS NULL OR us.expire_at>NOW())
            UNION ALL
            SELECT s.features_json
              FROM users u
              JOIN subscriptions s ON s.sub_id=u.subscription_id
             WHERE u.id=NEW.user_id
               AND u.subscription_id<>0
               AND (u.subscription_expire IS NULL OR u.subscription_expire>NOW())
            UNION ALL
            SELECT s.features_json
              FROM subscriptions s
             WHERE s.sub_id=0
           ) ent
     WHERE FIND_IN_SET(
               '999',
               REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(ent.features_json,''),'[',''),']',''),'"',''),' ','')
           )>0
        OR FIND_IN_SET(
               CAST(v_feature AS CHAR),
               REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(ent.features_json,''),'[',''),']',''),'"',''),' ','')
           )>0
        OR (
             v_feature NOT IN (7,14,17)
         AND FIND_IN_SET(
               '0',
               REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(ent.features_json,''),'[',''),']',''),'"',''),' ','')
             )>0
           )
        OR (
             v_feature=1
         AND TRIM(COALESCE(ent.features_json,'')) IN ('','[]')
           );

    IF v_user_ok=0 OR v_grants=0 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT='iAPT V191.3 task denied: no live feature entitlement';
    END IF;
END$$

CREATE TRIGGER trg_iapt_v1912_tasks_bu
BEFORE UPDATE ON tasks
FOR EACH ROW
BEGIN
    DECLARE v_user_ok INT DEFAULT 0;
    DECLARE v_grants INT DEFAULT 0;
    DECLARE v_feature INT DEFAULT 1;

    IF NEW.status IN ('pending','queued','running')
       AND (
            NOT (NEW.user_id <=> OLD.user_id)
         OR NOT (NEW.feature_id <=> OLD.feature_id)
         OR COALESCE(OLD.status,'')<>COALESCE(NEW.status,'')
       ) THEN
        SET v_feature = IFNULL(NULLIF(NEW.feature_id,0),1);

        SELECT COUNT(*) INTO v_user_ok
          FROM users u
         WHERE u.id=NEW.user_id AND COALESCE(u.banned,0)=0;

        SELECT COUNT(*) INTO v_grants
          FROM (
                SELECT s.features_json
                  FROM user_subscriptions us
                  JOIN subscriptions s ON s.sub_id=us.sub_id
                 WHERE us.user_id=NEW.user_id
                   AND (us.expire_at IS NULL OR us.expire_at>NOW())
                UNION ALL
                SELECT s.features_json
                  FROM users u
                  JOIN subscriptions s ON s.sub_id=u.subscription_id
                 WHERE u.id=NEW.user_id
                   AND u.subscription_id<>0
                   AND (u.subscription_expire IS NULL OR u.subscription_expire>NOW())
                UNION ALL
                SELECT s.features_json
                  FROM subscriptions s
                 WHERE s.sub_id=0
               ) ent
         WHERE FIND_IN_SET(
                   '999',
                   REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(ent.features_json,''),'[',''),']',''),'"',''),' ','')
               )>0
            OR FIND_IN_SET(
                   CAST(v_feature AS CHAR),
                   REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(ent.features_json,''),'[',''),']',''),'"',''),' ','')
               )>0
            OR (
                 v_feature NOT IN (7,14,17)
             AND FIND_IN_SET(
                   '0',
                   REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(ent.features_json,''),'[',''),']',''),'"',''),' ','')
                 )>0
               )
            OR (
                 v_feature=1
             AND TRIM(COALESCE(ent.features_json,'')) IN ('','[]')
               );

        IF v_user_ok=0 OR v_grants=0 THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT='iAPT V191.3 task denied: entitlement revoked or missing';
        END IF;
    END IF;
END$$
DELIMITER ;
