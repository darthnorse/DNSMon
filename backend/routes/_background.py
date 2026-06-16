"""Fire-and-forget background task helper shared by route modules.

Holds strong references to scheduled tasks so asyncio doesn't garbage-collect
them mid-run (a bare `create_task` result can be collected before it finishes).
"""
import asyncio

_background_tasks: set = set()


def run_in_background(coro):
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task
