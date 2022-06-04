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
	- [x] Extract the correct `ref` string from the decrypted parsed data
	- [x] Construct the QR code
	- [ ] Scan and test
  
            Scanning shows an error msg saying that device could not be linked now. However,
            our client gets partially linked as it throws a max linking error after ~5 tries.
            Need to figure out why linking fails.
	- [ ] Write a `WapParser` (Line #11128)
	- [ ] A 37 byte frame is sent to the server. what is it ?
- [ ] Setup the Ratchet
- [ ] Retrieve Messages

