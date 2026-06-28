# this file contains all network helpers for port scanner


import asyncio
import socket


def sock_addr(ip, port, family):
    if family == socket.AF_INET6:
        return (ip, port, 0, 0)
    return (ip, port)


class DynamicSemaphore:
    def __init__(self, value):
        self.value = value
        self.max_value = value
        self.current = 0
        self.cond = asyncio.Condition()

    async def acquire(self):
        async with self.cond:
            while self.current >= self.value:
                await self.cond.wait()
            self.current += 1

    async def release(self):
        async with self.cond:
            self.current -= 1
            self.cond.notify()

    async def set_value(self, new_val):
        async with self.cond:
            self.value = min(self.max_value, max(1, new_val))
            self.cond.notify_all()
