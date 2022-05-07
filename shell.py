import socketio
import asyncio

sio = socketio.AsyncClient(logger=True, engineio_logger=True)


@sio.event
async def connect():
	print(':. connection established')

@sio.event
async def connect_error(data):
	print(f'connection failed ~> {data}')

@sio.on('*')
async def catch_all(event, data):
	print(event ,data)

async def main():
	await sio.connect('wss://web.whatsapp.com/ws/chat/')
	await sio.wait()


if __name__ == '__main__':
	loop = asyncio.get_event_loop()
	try:
		loop.create_task(main())
		loop.run_forever()
	except Exception as e:
		print('caught a frikkin exception')
		loop.run_until_complete(sio.disconnect())
		loop.close()
	finally:
		print(':. client exiting')
