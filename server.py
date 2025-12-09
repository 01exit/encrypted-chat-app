import aiohttp
from aiohttp import web
import os

clients = set()

async def health(request):
    return web.Response(text="OK")

async def handle_ws(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    clients.add(ws)
    try:
        if len(clients) == 2:
            for client in clients:
                await client.send_str('ready')
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                for client in clients:
                    if client != ws:
                        await client.send_str(msg.data)
            elif msg.type == aiohttp.WSMsgType.ERROR:
                print('ws connection closed with exception %s' % ws.exception())
    finally:
        clients.remove(ws)
    return ws

app = web.Application()
app.add_routes([web.get('/health', health),
                web.get('/', handle_ws)])

if __name__ == '__main__':
    web.run_app(app, host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))