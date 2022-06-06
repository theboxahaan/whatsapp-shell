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
- [x] Get the QR
	- [x] Decrypt the server response on Noise Handshake successful
	- [x] Extract the correct `ref` string from the decrypted parsed data
	- [x] Construct the QR code
	- [ ] Scan and test
  
            Scanning shows an error msg saying that device could not be linked now. However,
            our client gets partially linked as it throws a max linking error after ~5 tries.
            Need to figure out why linking fails.
	- [x] Write a `WapParser` (Line #11128)
	- [x] Write a WapEncoder (Line #10727)
	- [x] A 37 byte frame is sent to the server. ~~what is it ?~~ -- possibly called the `result`
	- [ ] A ~250 byte response is sent from the server which I don't get yet. Get that msg
- [ ] Setup the Ratchet
- [ ] Retrieve Messages


## Notes
1. `t.decodeStanza()` on Line #10588 decodes the 588 byte blob received from the server after
finishing the Noise handshake. Decoding this gives the `id` and the `ref`s which are usded to
construct the 37 byte response which is needed to link successfully using the QR.

2. The final frame is poosibly constructed using the `castStanza` function which is called on 
Line #47522. This needs to be explored.

