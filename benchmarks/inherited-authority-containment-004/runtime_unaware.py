from __future__ import annotations
import asyncio

async def dispatch(delay_before_effect_s, effect_callback, *args):
    await asyncio.sleep(delay_before_effect_s)
    return await effect_callback(*args)

async def stale_dispatch(delay_before_check_s, delay_after_check_s, precheck_callback, commit_callback, *args):
    await asyncio.sleep(delay_before_check_s)
    decision = await precheck_callback(*args)
    await asyncio.sleep(delay_after_check_s)
    return await commit_callback(decision, *args)
