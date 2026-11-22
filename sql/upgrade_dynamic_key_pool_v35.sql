-- V35：V3 服务器动态Key提取与匿名密钥池
CREATE TABLE IF NOT EXISTS dynamic_key_pool (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    public_id VARCHAR(64) NOT NULL,
    key_hash CHAR(64) NOT NULL,
    post_key_enc LONGTEXT NOT NULL,
    xor_key_enc LONGTEXT NOT NULL,
    source_type VARCHAR(32) NOT NULL DEFAULT 'unknown',
    source_sha256 CHAR(64) NULL,
    source_name VARCHAR(255) NULL,
    first_user_id BIGINT NULL,
    verified TINYINT NOT NULL DEFAULT 0,
    success_count INT NOT NULL DEFAULT 1,
    use_count INT NOT NULL DEFAULT 0,
    enabled TINYINT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL,
    UNIQUE KEY uk_dynamic_key_pool_public(public_id),
    UNIQUE KEY uk_dynamic_key_pool_hash(key_hash),
    KEY idx_dynamic_key_pool_enabled(enabled,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 订阅 features_json 中：
-- 15 = 使用服务器密钥池中的单个动态Key（功能0通配）
-- 16 = 枚举服务器动态Key池（功能0通配）
-- 4  = 单独提取动态Key/服务器自动动态Key（沿用原功能ID）
