; MK300 static hardware evidence. VA = app.bin offset + 0x18000120.
; Names are analysis annotations, not original symbols. No physical pin labels inferred.
; Full linear disassembly includes data; only selected code ranges follow.

; Logical GUI size: 480 x 320
18032b0c:      	r0 = [r10+0x318]
18032b10:      	call -0x6984
18032b14:      	call -0x44b6
18032b18:      	r1 = 0x1e0  #
18032b1c:            		 [r4+0x0] = r0
18032b1e:      	r2 = 0x140
18032b22:      	call -0x421c
18032b26:            	r0 = [r4+0x0] 

; GPIO ID decoding and control wrappers
18053df0:            	r1 = r0
18053df2:            	r0 = 0x0
18053df4:      	if (r1 <= 0x71) {
18053df8:            		r0 = r1 >> 0x4
18053dfa:            		r0 = r0 << 0x2
18053dfc:		r1 = 0x1810a280
18053e02:      		r0 = [r0+r1]
18053e06:            	rts
18053e08:            	[--sp] = rets
18053e0a:            	r2 = r1
18053e0c:            	r3 = r0
18053e0e:            	call -0x20
18053e10:            	if (r0 == 0) goto 0x16
18053e12:      	r1 = r3 & 0xF
18053e16:            	r3 = 0x1
18053e18:      	r1 = r3 << r1
18053e1c:            	if (r2 == 0) goto 0x6
18053e1e:      	[r0+0xc] |= r1
18053e22:            	pc = [sp++]
18053e24:      	[r0+0xc] &= ~r1
18053e28:            	pc = [sp++]
18053e2a:            	[--sp] = rets
18053e2c:            	r2 = r0
18053e2e:            	call -0x40
18053e30:            	if (r0 == 0) goto 0x8
18053e32:      	r1 = r2 & 0xF
18053e36:      	[r0+0x8] |= 1 << r1
18053e3a:            	pc = [sp++]
18053e3c:            	[--sp] = rets
18053e3e:            	r2 = r1
18053e40:            	r3 = r0
18053e42:            	call -0x54
18053e44:            	if (r0 == 0) goto 0x22
18053e46:      	r1 = r3 & 0xF
18053e4a:            	r3 = 0x1
18053e4c:      	r1 = r3 << r1
18053e50:      	if (r2 == 0x3) goto 0x16
18053e54:      	if (r2 == 0x2) goto 0x1c
18053e58:      	if (r2 != 0x1) {
18053e5c:      		[r0+0x14] &= ~r1
18053e60:      		[r0+0x14] |= r1
18053e64:      	[r0+0x18] &= ~r1
18053e68:            	pc = [sp++]
18053e6a:      	[r0+0x14] |= r1
18053e6e:      	[r0+0x18] |= r1
18053e72:            	pc = [sp++]
18053e74:      	[r0+0x14] &= ~r1
18053e78:      	[r0+0x18] |= r1
18053e7c:            	pc = [sp++]
18053e7e:            	[--sp] = rets
18053e80:            	r2 = r0
18053e82:            	call -0x94
18053e84:            	if (r0 == 0) goto 0xc
18053e86:      	r1 = r2 & 0xF
18053e8a:      	[r0+0x1c] &= ~(1 << r1)
18053e8e:      	[r0+0x20] &= ~(1 << r1)
18053e92:            	pc = [sp++]

; Normal logical-key processing uses bit-remap table
18087d1a:            	[--sp] = {rets, r15-r4}
18087d1c:      	r1 = 0x1bc
18087d20:	r15 = 0x1844b5b0
18087d26:      	r2 = b[r15+r1] (u)
18087d2a:	r0 = 0xfc7534
18087d30:            	if (r2 == 0) goto 0xa
18087d32:      	[r0+0x0] = 0x1
18087d36:            	r2 = 0x0
18087d38:      	b[r15+r1] = r2
18087d3c:      	r1 = h[r15+0x70] (u)
18087d40:      	r2 = h[r15+0x72] (u)
18087d44:      	if (r2 == r1) goto 0x22
18087d48:      	h[r15+0x72] = r1
18087d4c:      	[r0+0x0] = 0x10000
18087d50:      	r0 = r15 + 0x72
18087d54:	r1 = 0xfc280c
18087d5a:            	[r1+0x0] = r0
18087d5c:      	[r1+0x4] = 0x2
18087d60:      	r0 = 0x1bc
18087d64:            	r1 = 0x1
18087d66:      	b[r15+r0] = r1
18087d6a:	r14 = 0x180f7a90
18087d70:      	r5 = r14 + 0xa89
18087d74:            	r9 = 0
18087d76:            	r7 = 0x3c
18087d78:	r8 = 0x3000001
18087d7e:            	r6 = 0x0
18087d80:            	r0 = b[r5+-0x1] (u)
18087d82:            	r0 = r0 << 0x2
18087d84:      	r1 = r0 + r15
18087d88:      	r1 = r1 + 0xfa2
18087d8c:            	r2 = b[r1+0x0] (u)
18087d8e:      	if (r2 != 0x1) goto 0x2a
18087d92:            	r2 = b[r5+0x0] (u)
18087d94:            	r2 = r2 << 0x2
18087d96:      	r3 = r2 + r15
18087d9a:      	r3 = r3 + 0xfa2
18087d9e:            	r4 = b[r3+0x0] (u)
18087da0:      	if (r4 != 0x1) goto 0x18
18087da4:            	b[r3+0x0] = r7
18087da6:      	r1 = r15 + 0xfa0  #
18087daa:            		 b[r1+0x0] = r7
18087dac:      	h[r1+r2] = r9
18087db0:      	h[r1+r0] = r9
18087db4:      	r0 = r6 | r8
18087db8:      	call -0x128
18087dbc:      	r6 = r6 + 0x10000
18087dc0:            	r5 += 0x2
18087dc2:	if (r6 != 0x60000) goto -0x48
18087dc8:            	r13 = 0
18087dca:            	r6 = 0xc
18087dcc:            	r10 = 0
18087dce:      	r0 = r10 + r14
18087dd2:      	r1 = 0x16b3
18087dd6:      	r0 = b[r0+r1] (u)
18087dda:      	r1 = r10 << 0x2
18087dde:      	r5 = r1 + r15
18087de2:      	r2 = [r15+0x1c0]
18087de6:      	r11 = r5 + 0xfa2
18087dea:      	r1 = b[r11+0x0] (u)
18087dee:      	r0 = r2 & (1 << r0)
18087df2:            	if (r0 == 0) goto 0x28
18087df4:      	r0 = r1 + -0x1
18087df8:            	r0 = r0.b0 (u)
18087dfa:      	if (r0 > 0x12) goto 0x7c
18087dfe:      	r0 = r10 << 0x10
18087e02:      	if (r1 != 0x1) {
18087e06:            		r1 += 0x14
18087e08:            		r0 |= r1
18087e0a:      	call -0x17a
18087e0e:      	b[r11+0x0] = r13
18087e12:      	r0 = 0x7d0
18087e16:      	h[r5+r0<<1] = r13
18087e1a:            	goto 0x278

; GPIO output and special-I/O wrappers
1808c564:            	[--sp] = rets
1808c566:            	r2 = r1
1808c568:            	r3 = r0
1808c56a:      	call -0x3877e
1808c56e:            	if (r0 == 0) goto 0x1e
1808c570:      	r1 = r3 & 0xF
1808c574:            	r3 = 0x1
1808c576:      	r1 = r3 << r1
1808c57a:            	if (r2 == 0) goto 0xa
1808c57c:      	if (r2 == 0x1) {
1808c580:      		[r0+0x4] |= r1
1808c584:            	goto 0x4
1808c586:      	[r0+0x4] &= ~r1
1808c58a:      	[r0+0x8] &= ~r1
1808c58e:            	pc = [sp++]
1808c590:            	[--sp] = rets
1808c592:            	r2 = r0
1808c594:      	call -0x387a8
1808c598:            	if (r0 == 0) goto 0xc
1808c59a:      	r1 = r2 & 0xF
1808c59e:      	[r0+0x24] &= ~(1 << r1)
1808c5a2:      	[r0+0x28] &= ~(1 << r1)
1808c5a6:            	pc = [sp++]
1808c5a8:            	[--sp] = rets
1808c5aa:            	r0 += -0x80
1808c5ac:      	if (r0 > 0x1) goto 0x2a
1808c5b0:            	r2 = 0x1
1808c5b2:      	r0 = r2 << r0
1808c5b6:            	if (r1 == 0) goto 0x10
1808c5b8:            	r1 = r0.b0 (u)
1808c5ba:	r0 = 0x809b
1808c5c0:	call -0x17f8b52a
1808c5c6:            	pc = [sp++]
1808c5c8:            	r1 = 0xff
1808c5ca:      	r1 = r1 & ~r0
1808c5ce:	r0 = 0x809b
1808c5d4:	call -0x17f8b296
1808c5da:            	pc = [sp++]
1808c5dc:            	[--sp] = {rets, r5, r4}
1808c5de:      	r5 = r0 + -0x80
1808c5e2:            	r4 = r1
1808c5e4:      	if (r5 > 0x1) goto 0x3c
1808c5e8:            	r0 = 0xff
1808c5ea:      	r1 = r0 & ~(1 << r5)
1808c5ee:	r0 = 0x809b
1808c5f4:	call -0x17f8b2b6
1808c5fa:            	if (r4 == 0) goto 0x14
1808c5fc:            	r0 = 0x1
1808c5fe:            	r0 <<= r5
1808c600:            	r1 = r0.b0 (u)
1808c602:	r0 = 0x809a
1808c608:	call -0x17f8b572
1808c60e:            	{pc, r5, r4} = [sp++]
1808c610:            	r0 = -0x1
1808c612:      	r0 = r0 ^ (1 << r5)
1808c616:            	r1 = r0.b0 (u)
1808c618:	r0 = 0x809a
1808c61e:	call -0x17f8b2e0
1808c624:            	{pc, r5, r4} = [sp++]

; Normal matrix initialization and event callback registration
1808e26e:	r0 = 0x3fffffff
1808e274:      	[r13+0x1c0] = r0
1808e278:      	[r13+0x1dc] = r0
1808e27c:      	r0 = r6 + r14
1808e280:      	r5 = b[r0+0xa8] (u)
1808e284:            	r1 = 0x1
1808e286:            	r0 = r5
1808e288:      	call -0x3a484
1808e28c:            	r1 = 0x1
1808e28e:            	r0 = r5
1808e290:      	call -0x1d30
1808e294:            	r0 = r5
1808e296:      	call -0x1d0a
1808e29a:            	r6 += 0x1
1808e29c:      	if (r6 != 0x4) goto -0x24
1808e2a0:            	r0 = 0x80
1808e2a2:            	r1 = 0x0
1808e2a4:            	r6 = 0x0
1808e2a6:      	call -0x1d02
1808e2aa:            	r0 = 0x80
1808e2ac:            	r1 = 0x1
1808e2ae:      	call -0x1cd6
1808e2b2:            	r0 = 0x81
1808e2b4:            	r1 = 0x0
1808e2b6:      	call -0x1d12
1808e2ba:            	r0 = 0x81
1808e2bc:            	r1 = 0x1
1808e2be:      	call -0x1ce6
1808e2c2:      	r7 = 0x197
1808e2c6:      	r0 = r6 + r14
1808e2ca:      	r5 = b[r0+r7] (u)
1808e2ce:            	r1 = 0x1
1808e2d0:            	r0 = r5
1808e2d2:      	call -0x3a4ce
1808e2d6:            	r0 = r5
1808e2d8:      	call -0x3a4b2
1808e2dc:            	r1 = 0x1
1808e2de:            	r0 = r5
1808e2e0:      	call -0x3a4a8
1808e2e4:            	r0 = r5
1808e2e6:      	call -0x3a46c
1808e2ea:            	r6 += 0x1
1808e2ec:      	if (r6 != 0x5) goto -0x2a
1808e2f0:	r2 = 0x18088a9e
1808e2f6:            	r0 = 0x13
1808e2f8:            	r1 = 0x2
1808e2fa:            	r3 = 0x0
1808e2fc:            	r5 = 0x0
1808e2fe:      	call -0x566d0
1808e302:	r0 = 0xfc083c
1808e308:            	[r0+0x0] = r5
1808e30a:      	r1 = 0xf9f  #
1808e30e:            		 [r0+0x4] = r5
1808e310:            	[r0+0x8] = r1
1808e312:      	[r0+0x0] |= 0x4000
1808e316:      	r1 = 0x3001
1808e31a:            	[r0+0x0] = r1
1808e31c:	r1 = 0x18087d1a
1808e322:            	r0 = 0x0
1808e324:            	r2 = 0x14
1808e326:      	call -0x3ea56

; Boot key scan: 6 drive rows, 5 sense columns, 21-bit remap
1808e90c:            	[--sp] = {rets, r15-r4}
1808e90e:            	sp += -0x20
1808e910:	r6 = 0x1844b5b0
1808e916:      	r4 = r6 + 0x8a4
1808e91a:	r5 = 0x180f7a90
1808e920:      	r0 = r5 + 0x1dd4
1808e924:            	r1 = r4
1808e926:            	rep 0x4 0x5 {
1808e928:            		r2 = b[r0++=0x1] (u)
1808e92a:            		b[r1++=0x1] = r2
1808e92c:      	r0 = 0x8a9
1808e930:            	r1 = 0x0
1808e932:      	b[r6+r0] = r1
1808e936:      	r0 = r6 + 0x688
1808e93a:	call -0x8b79a
1808e940:      	call -0x3eb6c
1808e944:      	r0 = 0x1e4
1808e948:      	r1 = b[r6+r0] (u)
1808e94c:	r2 = 0x1813af20
1808e952:            	if (r1 != 0) goto 0x12
1808e954:      	[r2+0x64] = r4
1808e958:      	r1 = r5 + 0x1dda
1808e95c:      	[r2+0x68] = r1
1808e960:            	r1 = 0x1
1808e962:      	b[r6+r0] = r1
1808e966:            	r0 += 0x38
1808e968:      	r0 = b[r6+r0] (u)
1808e96c:	if (r0 == 0x0) goto 0x206
1808e972:            	r0 = 0x24
1808e974:            	r1 = 0x1
1808e976:      	r15 = 0x1
1808e97a:      	call -0x3ab76
1808e97e:            	r0 = 0x24
1808e980:            	r1 = 0x1
1808e982:      	call -0x2422
1808e986:            	r0 = 0x24
1808e988:      	call -0x23fc
1808e98c:            	r0 = 0x25
1808e98e:            	r1 = 0x1
1808e990:      	call -0x3ab8c
1808e994:            	r0 = 0x25
1808e996:            	r1 = 0x1
1808e998:      	call -0x2438
1808e99c:            	r0 = 0x25
1808e99e:      	call -0x2412
1808e9a2:            	r0 = 0xb
1808e9a4:            	r1 = 0x1
1808e9a6:      	call -0x3aba2
1808e9aa:            	r0 = 0xb
1808e9ac:            	r1 = 0x1
1808e9ae:      	call -0x244e
1808e9b2:            	r0 = 0xb
1808e9b4:      	call -0x2428
1808e9b8:            	r0 = 0x52
1808e9ba:            	r1 = 0x1
1808e9bc:      	call -0x3abb8
1808e9c0:            	r0 = 0x52
1808e9c2:            	r1 = 0x1
1808e9c4:      	call -0x2464
1808e9c8:            	r0 = 0x52
1808e9ca:      	call -0x243e
1808e9ce:            	r0 = 0x80
1808e9d0:            	r1 = 0x0
1808e9d2:            	r4 = 0x0
1808e9d4:      	call -0x2430
1808e9d8:            	r0 = 0x80
1808e9da:            	r1 = 0x1
1808e9dc:      	call -0x2404
1808e9e0:            	r0 = 0x81
1808e9e2:            	r1 = 0x0
1808e9e4:      	call -0x2440
1808e9e8:            	r0 = 0x81
1808e9ea:            	r1 = 0x1
1808e9ec:      	call -0x2414
1808e9f0:            	r0 = 0x26
1808e9f2:            	r1 = 0x1
1808e9f4:      	call -0x3abf0
1808e9f8:            	r0 = 0x26
1808e9fa:      	call -0x3abd4
1808e9fe:            	r0 = 0x26
1808ea00:            	r1 = 0x1
1808ea02:      	call -0x3abca
1808ea06:            	r0 = 0x26
1808ea08:      	call -0x3ab8e
1808ea0c:            	r0 = 0x27
1808ea0e:            	r1 = 0x1
1808ea10:      	call -0x3ac0c
1808ea14:            	r0 = 0x27
1808ea16:      	call -0x3abf0
1808ea1a:            	r0 = 0x27
1808ea1c:            	r1 = 0x1
1808ea1e:      	call -0x3abe6
1808ea22:            	r0 = 0x27
1808ea24:      	call -0x3abaa
1808ea28:            	r0 = 0x28
1808ea2a:            	r1 = 0x1
1808ea2c:      	call -0x3ac28
1808ea30:            	r0 = 0x28
1808ea32:      	call -0x3ac0c
1808ea36:            	r0 = 0x28
1808ea38:            	r1 = 0x1
1808ea3a:      	call -0x3ac02
1808ea3e:            	r0 = 0x28
1808ea40:      	call -0x3abc6
1808ea44:            	r0 = 0x29
1808ea46:            	r1 = 0x1
1808ea48:      	call -0x3ac44
1808ea4c:            	r0 = 0x29
1808ea4e:      	call -0x3ac28
1808ea52:            	r0 = 0x29
1808ea54:            	r1 = 0x1
1808ea56:      	call -0x3ac1e
1808ea5a:            	r0 = 0x29
1808ea5c:      	call -0x3abe2
1808ea60:            	r0 = 0x38
1808ea62:            	r1 = 0x1
1808ea64:      	call -0x3ac60
1808ea68:            	r0 = 0x38
1808ea6a:      	call -0x3ac44
1808ea6e:            	r0 = 0x38
1808ea70:            	r1 = 0x1
1808ea72:      	call -0x3ac3a
1808ea76:            	r0 = 0x38
1808ea78:      	call -0x3abfe
1808ea7c:	r10 = 0x180fba90
1808ea82:      	r11 = 0x491
1808ea86:      	r13 = 0x924
1808ea8a:      	r6 = 0x197
1808ea8e:      	r9 = 0x16b3
1808ea92:            	r7 = 0x0
1808ea94:            	r14 = 0  #
1808ea96:            		 [sp+12] = r7
1808ea98:            	r12 = 0  #
1808ea9a:            		 [sp+16] = r4
1808ea9c:            	r7 = 0x0
1808ea9e:            	goto 0x8
1808eaa0:      	r14 = r14 + 0x5
1808eaa4:      	r12 = r12 + 0x1
1808eaa8:            	r0 = 0x24
1808eaaa:            	r1 = 0x1
1808eaac:      	call -0x299a
1808eab0:            	r0 = 0x52
1808eab2:            	r1 = 0x1
1808eab4:      	call -0x29a2
1808eab8:            	r0 = 0x81
1808eaba:            	r1 = 0x1
1808eabc:      	call -0x24e4
1808eac0:            	r0 = 0x80
1808eac2:            	r1 = 0x1
1808eac4:      	call -0x24ec
1808eac8:            	r0 = 0xb
1808eaca:            	r1 = 0x1
1808eacc:      	call -0x29ba
1808ead0:            	r0 = 0x25
1808ead2:            	r1 = 0x1
1808ead4:      	call -0x29c2
1808ead8:      	ifs (r12 >= 0x6) goto 0x4e
1808eadc:      	r0 = r12 * 0xC
1808eae0:      	r4 = r0 + r10
1808eae4:      	r0 = [r4+r11<<2]
1808eae8:      	r1 = r12 & 0xFFFFFFFE
1808eaec:      	if (r1 != 0x2) goto 0x8
1808eaf0:            	r1 = 0x0
1808eaf2:      	call -0x251a
1808eaf6:            	goto 0x6
1808eaf8:            	r1 = 0x0
1808eafa:      	call -0x29e8
1808eafe:      	r0 = h[r4+r13<<1] (u)
1808eb02:	call -0x8a94c
1808eb08:            	r8 = 0
1808eb0a:            	r4 = r14
1808eb0c:      	r0 = r8 + r5
1808eb10:      	r0 = b[r0+r6] (u)
1808eb14:      	call -0x24f2
1808eb18:            	if (r0 != 0) goto 0x4
1808eb1a:      	r7 = r7 | (1 << r4)
1808eb1e:      	r8 = r8 + 0x1
1808eb22:            	r4 += 0x1
1808eb24:      	if (r8 != 0x5) goto -0x1c
1808eb28:            	goto -0x8a
1808eb2a:            	r1_r0 = 0
1808eb2c:            	r2 = r0 + r5
1808eb2e:      	r2 = b[r2+r9] (u)
1808eb32:      	r3 = r15 << r0
1808eb36:      	r4 = r15 << r2
1808eb3a:            	r2 = 0x0
1808eb3c:      	if ((r4 & r7) != 0) {
1808eb40:            		r2 = r3
1808eb42:            	r0 += 0x1
1808eb44:            	r1 |= r2
1808eb46:      	if (r0 != 0x15) goto -0x1e
1808eb4a:	if (r1 != 0x180000) goto 0xc
1808eb50:            	r7 = [sp+12]
1808eb52:            	r7 += 0x1
1808eb54:            	r4 = [sp+16]
1808eb56:      	ifs (r7 <= 0x63) goto 0xa
1808eb5a:            	goto 0x256
1808eb5c:            	r7 = 0x0
1808eb5e:            	r4 = [sp+16]
1808eb60:      	ifs (r4 > 0x63) goto 0x10
1808eb64:            	r0 = 0xa
1808eb66:	call -0x8ab4c
1808eb6c:            	r4 += 0xa
1808eb6e:	ifs (r4 < 0x3e8) goto -0xe0
1808eb74:            	r4 = 0x1
1808eb76:            	goto 0x23c

; Initialization structure includes 44100 Hz; exact audio route not assigned
1808efc0:	r7 = 0x1844b5b0
1808efc6:      	r1 = r7 + 0xdc4
1808efca:            	r2 = r1 + 0x8
1808efcc:            	r0 = 0x0
1808efce:            	rep 0x2 0x6 {
1808efd0:            		[r2++=0x4] = r0
1808efd2:	r2 = 0x18093716
1808efd8:      	r3 = r7 + 0xa5c  #
1808efdc:            		 [r1+0x0] = r2
1808efde:            	r2 = r3
1808efe0:            	rep 0x2 0x7 {
1808efe2:            		[r2++=0x4] = r0
1808efe4:      	r2 = 0x13f
1808efe8:      	[r7+r2<<2] = r3
1808efec:            	r2 = 0x7f
1808efee:      	r4 = 0xa74  #
1808eff2:            		 h[r3+0x8] = r2
1808eff4:            	h[r3+0x0] = r2
1808eff6:            	h[r3+0x2] = r2
1808eff8:            	h[r3+0x4] = r2
1808effa:            	h[r3+0x6] = r0
1808effc:            	h[r3+0xa] = r6
1808effe:      	b[r7+r4] = r0
1808f002:	r4 = 0xac44
1808f008:            	[r3+0x20] = r4
1808f00a:            	h[r3+0x14] = r2
1808f00c:            	h[r3+0xc] = r2
1808f00e:            	h[r3+0xe] = r2
1808f010:      	r2 = 0xa75  #
1808f014:            		 h[r3+0x10] = r2
1808f016:            	h[r3+0x12] = r0
1808f018:            	h[r3+0x16] = r6
1808f01a:      	b[r7+r2] = r0
1808f01e:            	[r3+0x1c] = r4

; SDK version-string reference
18090170:            	[--sp] = {rets, r5, r4}
18090172:	r1 = 0x180fc088
18090178:      	r0 = r1 + 0xa9
1809017c:      	call -0x586c0

