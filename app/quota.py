import json, math, random, re
from datetime import date
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from . import db

FEATURE_BASIC = 1
FEATURE_DEX_ENUM = 2
FEATURE_SERVER_SOKEY = 15  # 服务器获取sokey；功能0通配。
FEATURE_HIDDEN_ENUM = FEATURE_SERVER_SOKEY  # 兼容旧名称。
FEATURE_DYNAMIC_KEY = 4
FEATURE_NUMERIC_FN_RESTORE = 5
FEATURE_V6_STATIC = 6
FEATURE_WHITELIST_BYPASS = 7
FEATURE_SOURCE_RESTORE = 8
FEATURE_JOINT_KEY_ENUM = 14  # sokey+dexkey 联合枚举；必须在订阅中显式包含，功能0不通配。
FEATURE_DYNAMIC_KEY_POOL = 15  # 使用服务器动态Key池中的单个Key / 服务器获取sokey；功能0通配。
FEATURE_DYNAMIC_KEY_POOL_ENUM = 16  # 枚举服务器动态Key池；功能0通配。
FEATURE_ULTIMATE_ALL = 999  # 真全功能；包含所有当前及未来特殊功能，优先级高于功能0。

_QUOTA_SCALE = Decimal('0.01')

def quota_decimal(value, default=0) -> Decimal:
    """
    额度统一转成 Decimal(2位小数)。
    兼容旧库/旧客户端 32 位 INT 溢出的负数，例如 -148xxxx 会还原成无符号值。
    """
    raw = value if value is not None and str(value) != '' else default
    try:
        d = Decimal(str(raw))
    except (InvalidOperation, ValueError, TypeError):
        try:
            d = Decimal(str(default or 0))
        except Exception:
            d = Decimal('0')
    if d < 0 and d >= Decimal(-2147483648) and d == d.to_integral_value():
        d = Decimal(4294967296) + d
    if d < 0:
        d = Decimal('0')
    return d.quantize(_QUOTA_SCALE, rounding=ROUND_HALF_UP)


def quota_public_value(value, default=0):
    d = quota_decimal(value, default)
    if d == d.to_integral_value():
        return int(d)
    return float(d)


def normalize_quota_value(value, default: int = 0):
    return quota_public_value(value, default)



def parse_feature_ids(features_json) -> set[int]:
    """Parse features_json from JSON list, CSV string, scalar int, or mixed values."""
    raw = features_json
    if raw is None or raw == '':
        return set()
    vals = []
    try:
        if isinstance(raw, str):
            s = raw.strip()
            if not s:
                return set()
            try:
                parsed = json.loads(s)
            except Exception:
                parsed = re.split(r'[,，\s]+', s)
        else:
            parsed = raw
        if isinstance(parsed, (list, tuple, set)):
            vals = list(parsed)
        else:
            vals = [parsed]
    except Exception:
        vals = []
    out = set()
    for v in vals:
        try:
            if str(v).strip() != '':
                out.add(int(v))
        except Exception:
            pass
    return out


def feature_supported(features_json, feature_id: int) -> bool:
    ids = parse_feature_ids(features_json)
    fid = int(feature_id)

    # 999=真全功能。它覆盖普通功能、当前特殊功能 7/14/17，
    # 以及以后新增但功能0不通配的特殊功能。
    if FEATURE_ULTIMATE_ALL in ids:
        return True

    # 0=普通全功能通配，但不包含必须显式授权的特殊功能。
    if fid in (FEATURE_WHITELIST_BYPASS, FEATURE_JOINT_KEY_ENUM):
        return fid in ids
    if 0 in ids:
        return True
    if fid == FEATURE_BASIC and not ids:
        return True
    return fid in ids


def _active_subscription_candidates(user_id: int) -> list:
    rows = []
    try:
        rows.extend(list(db.all("""
            SELECT s.*, us.expire_at AS bind_expire_at, 'user_subscriptions' AS bind_source
            FROM user_subscriptions us JOIN subscriptions s ON us.sub_id=s.sub_id
            WHERE us.user_id=%s AND (us.expire_at IS NULL OR us.expire_at>NOW())
        """, (user_id,)) or []))
    except Exception as e:
        print('[WARN] read user_subscriptions failed:', e)

    try:
        rows.extend(list(db.all("""
            SELECT s.*, u.subscription_expire AS bind_expire_at, 'users.subscription_id' AS bind_source
            FROM users u JOIN subscriptions s ON u.subscription_id=s.sub_id
            WHERE u.id=%s AND u.subscription_id<>0
              AND (u.subscription_expire IS NULL OR u.subscription_expire>NOW())
        """, (user_id,)) or []))
    except Exception as e:
        print('[WARN] read users.subscription_id failed:', e)

    dedup = {}
    for r in rows:
        try:
            sid = int(r.get('sub_id') or 0)
        except Exception:
            sid = 0
        if sid not in dedup:
            dedup[sid] = r
    out = list(dedup.values())

    def sort_key(r):
        try:
            quota = float(r.get('daily_quota') or 0)
        except Exception:
            quota = 0.0
        try:
            sid = int(r.get('sub_id') or 0)
        except Exception:
            sid = 0
        return (quota, sid)

    out.sort(key=sort_key, reverse=True)
    return out


def active_subscription(user_id: int, feature_id: int):
    for sub in _active_subscription_candidates(user_id):
        if feature_supported(sub.get('features_json'), feature_id):
            return sub

    default = db.one("SELECT * FROM subscriptions WHERE sub_id=0")
    if default and feature_supported(default.get('features_json'), feature_id):
        return default
    return None


def active_subscription_debug(user_id: int, feature_id: int):
    rows = _active_subscription_candidates(user_id)
    selected = active_subscription(user_id, feature_id)
    return {
        'user_id': user_id,
        'feature_id': feature_id,
        'candidates': [
            {
                'sub_id': r.get('sub_id'),
                'sub_name': r.get('sub_name'),
                'features_json': r.get('features_json'),
                'daily_quota': str(r.get('daily_quota')),
                'bind_source': r.get('bind_source'),
                'bind_expire_at': str(r.get('bind_expire_at') or ''),
                'supported': feature_supported(r.get('features_json'), feature_id),
            } for r in rows
        ],
        'selected': None if not selected else {
            'sub_id': selected.get('sub_id'),
            'sub_name': selected.get('sub_name'),
            'features_json': selected.get('features_json'),
            'daily_quota': str(selected.get('daily_quota')),
        },
    }


def ensure_daily(user_id: int, feature_id: int):
    sub = active_subscription(user_id, feature_id)
    if not sub:
        return {'id': 0, 'user_id': user_id, 'feature_id': feature_id, 'total_quota': 0, 'extra_quota': 0, 'used_quota': 0}

    today = date.today()
    try:
        sub_total = int(float(sub.get('daily_quota') or 50))
    except Exception:
        sub_total = 50
    row = db.one("SELECT * FROM daily_quotas WHERE user_id=%s AND quota_date=%s AND feature_id=%s", (user_id, today, feature_id))
    if not row:
        db.exec("INSERT INTO daily_quotas(user_id,quota_date,feature_id,total_quota,extra_quota,used_quota) VALUES(%s,%s,%s,%s,0,0)", (user_id, today, feature_id, sub_total))
        row = db.one("SELECT * FROM daily_quotas WHERE user_id=%s AND quota_date=%s AND feature_id=%s", (user_id, today, feature_id))
    else:
        # 关键修复：用户升级/切换到更高订阅后，旧 daily_quotas 行可能仍是 0/250/200，导致提交全部被额度/权限拦截。
        # 只向上同步，不向下扣减，避免当天已发放额度被错误降低。
        try:
            cur_total = int(row.get('total_quota') or 0)
        except Exception:
            cur_total = 0
        if sub_total > cur_total:
            db.exec("UPDATE daily_quotas SET total_quota=%s WHERE id=%s", (sub_total, row['id']))
            row = db.one("SELECT * FROM daily_quotas WHERE id=%s", (row['id'],))
    row.setdefault('extra_quota', 0)
    return row

def available_quota(user_id: int, feature_id: int = FEATURE_BASIC) -> dict:
    row = ensure_daily(user_id, feature_id)
    base_total = quota_decimal(row.get('total_quota'), 0)
    extra_total = quota_decimal(row.get('extra_quota'), 0)
    total_quota = base_total + extra_total
    used = quota_decimal(row.get('used_quota'), 0)
    left = max(Decimal('0'), total_quota - used)
    sub_left = max(Decimal('0'), base_total - min(used, base_total))
    extra_used = max(Decimal('0'), used - base_total)
    extra_left = max(Decimal('0'), extra_total - extra_used)
    user = db.one("SELECT balance FROM users WHERE id=%s", (user_id,))
    balance = quota_decimal(user.get('balance'), 0) if user else Decimal('0')
    return {
        'subscription_left': quota_public_value(sub_left),
        'extra_left': quota_public_value(extra_left),
        'total': quota_public_value(left),
        'balance': quota_public_value(balance),
        'can_convert_quota': quota_public_value(balance * Decimal('10')),
    }


def cost_for_bytes(size_bytes: int) -> int:
    return max(1, math.ceil(max(0, size_bytes) / 10240)) if size_bytes > 0 else 0


def deduct_quota(user_id: int, feature_id: int, cost) -> dict:
    cost_d = quota_decimal(cost, 0)
    if cost_d <= 0:
        return {'quota_cost': 0}
    row = ensure_daily(user_id, feature_id)
    left = quota_decimal(available_quota(user_id, feature_id)['total'], 0)
    if left < cost_d:
        raise ValueError(f'额度不足：需要 {quota_public_value(cost_d)}，当前剩余 {quota_public_value(left)}')
    db.exec("UPDATE daily_quotas SET used_quota=used_quota+%s WHERE id=%s", (str(cost_d), row['id']))
    return {'quota_cost': quota_public_value(cost_d)}


def convert_balance_to_quota(user_id: int, feature_id: int, balance_amount: int) -> dict:
    balance_amount = int(balance_amount)
    if balance_amount <= 0:
        raise ValueError('兑换余额必须大于0')
    user = db.one('SELECT balance FROM users WHERE id=%s', (user_id,))
    if not user or quota_decimal(user.get('balance'), 0) < Decimal(balance_amount):
        raise ValueError('余额不足')
    row = ensure_daily(user_id, feature_id)
    add_quota = Decimal(balance_amount * 10).quantize(_QUOTA_SCALE)
    db.exec('UPDATE users SET balance=balance-%s WHERE id=%s', (balance_amount, user_id))
    db.exec('UPDATE daily_quotas SET extra_quota=extra_quota+%s WHERE id=%s', (str(add_quota), row['id']))
    db.exec('INSERT INTO quota_conversions(user_id,feature_id,balance_amount,quota_amount) VALUES(%s,%s,%s,%s)', (user_id, feature_id, balance_amount, str(add_quota)))
    return {'balance_used': balance_amount, 'quota_added': quota_public_value(add_quota), 'quota': available_quota(user_id, feature_id)}


def checkin(user_id: int) -> dict:
    today = date.today()
    if db.one('SELECT id FROM checkins WHERE user_id=%s AND checkin_date=%s', (user_id, today)):
        return {'ok': False, 'message': '今天已经签到过了', 'reward': 0}
    reward = random.randint(1, 10)
    db.exec('INSERT INTO checkins(user_id,checkin_date,reward_balance) VALUES(%s,%s,%s)', (user_id, today, reward))
    db.exec('UPDATE users SET balance=balance+%s WHERE id=%s', (reward, user_id))
    return {'ok': True, 'message': '签到成功', 'reward': reward}


def checkin_today(user_id: int) -> bool:
    return bool(db.one('SELECT id FROM checkins WHERE user_id=%s AND checkin_date=%s', (user_id, date.today())))
