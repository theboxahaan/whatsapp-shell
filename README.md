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


## Notes
1. `t.decodeStanza()` on Line #10588 decodes the 588 byte blob received from the server after
finishing the Noise handshake. Decoding this gives the `id` and the `ref`s which are usded to
construct the 37 byte response which is needed to link successfully using the QR.

2. The final frame is poosibly constructed using the `castStanza` function which is called on 
Line #47522. This needs to be explored.


## `WapParser`
> Ref function `Y()` on Line #10950

1. `readUint8`. If `0` then proceed, else it might be `gzip` deflated.
2. `t = readUint8`. If `t == 248`, then `n = readUint8`
3. ref `F(e,t)` on Line #10862,  if `readUint8 == ...` (compare against various values )
For the fist client response, `readUint8 = 30` and the mapped string is `iq`. This string is returned.
4. `a="iq"` is returned on Line #10962 
5. continue to Line #10963 that assigns the `id` to an attribute of `r` in one of its iterations.
6. ... complete it in code.
