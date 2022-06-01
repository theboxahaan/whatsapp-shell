# `whatsapp-shell`

```bash
$ python wshell.py
```
## Todo
- [x] Finish the `NOISE_XX_AES_128` handshake
  - [x] Reverse the `.proto` file for the structure of the protobuf
  
        This was easy enough in the Debugger where the structure can be viewed quite easily.
        Will put up an image detailing it soon. Possibly make an extract script from it as well.
	- [x] Finish decrypting the shello.static and shello.payload blobs	
	- [x] Construct the client finish message
- [ ] Get the QR
	- [x] Decrypt the server response on Noise Handshake successful
	- [ ] Extract the correct `ref` string from the decrypted parsed data
	- [ ] Construct the QR code
	- [ ] Scan and test!
- [ ] Setup the Ratchet
- [ ] Retrieve Messages

