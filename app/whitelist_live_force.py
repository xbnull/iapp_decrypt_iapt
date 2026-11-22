# -*- coding: utf-8 -*-
"""V111 compatibility shim.

Older builds installed an async middleware that executed CREATE TABLE, ALTER TABLE,
INFORMATION_SCHEMA scans and UPDATE statements on every GET /api/admin/whitelist.
A metadata-lock wait in that middleware blocked the single uvicorn event loop, making
all APIs appear dead until restart.  The real V58 whitelist routes remain registered
in app.main; schema migration is performed once by the deployment script.
"""
from __future__ import annotations

DEBUG_SOURCE = 'V111_WHITELIST_MIDDLEWARE_DISABLED'


def install(app):
    setattr(app.state, '_iapt_whitelist_live_force_v111_disabled', True)
    return None
