# `whatsapp-shell`

```bash
$ python wshell.py
```
## Todo
- [ ] Finish the `NOISE_XX_AES_128` handshake
  - [x] Reverse the `.proto` file for the structure of the protobuf
  
        This was easy enough in the Debugger where the structure can be viewed quite easily.
        Will put up an image detailing it soon. Possibly make an extract script from it as well.
	- [x] Finish decrypting the shello.static and shello.payload blobs	
	- [ ] Construct the client finish message
- [ ] Get the QR
- [ ] Setup the Ratchet
- [ ] Retrieve Messages

### Notes
1. Client-Server Handshake
	- Send Client Hello (43 bytes)
	- Receive Server Hello (350 bytes)
	- client Response (334 bytes)
