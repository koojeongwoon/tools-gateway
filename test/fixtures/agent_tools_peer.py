"""Loopback-only integration peer: production MCP app + real isolated CLI workers."""
import asyncio
import socket
import sys

import uvicorn
from agent_tools.server import create_app
from agent_tools.api import ApiService
from agent_tools.broker import BrokerResponse

class SyntheticBroker:
    def request_forward(self, operation, **kwargs):
        return BrokerResponse(200, {"content-type": "application/octet-stream"}, kwargs["body"])

class SyntheticVerifier:
    async def verify(self, token):
        return token == 'synthetic-gateway-delegation'

async def main():
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    print('LISTEN:' + str(listener.getsockname()[1]), flush=True)
    server = uvicorn.Server(uvicorn.Config(create_app(verifier=SyntheticVerifier(), api_service=ApiService(broker_factory=SyntheticBroker)), log_level='error', access_log=False))
    await server.serve(sockets=[listener])

asyncio.run(main())
