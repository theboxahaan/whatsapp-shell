import websockets
import asyncio



async def main():
	url = "wss://web.whatsapp.com/ws/chat"
	async with websockets.connect(url, origin="https://web.whatsapp.com") as ws:
		print("connected to the server...")
		await asyncio.sleep(5)

if __name__ == '__main__':
	
	loop = asyncio.get_event_loop()
	try:
		loop.create_task(main())
		loop.run_forever()
	except Exception as e:
		print('caught a frikkin exception')
		# loop.run_until_complete()
		loop.close()
	finally:
		print(':. client exiting')
