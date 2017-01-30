# Android bootloader (aboot) parser

Script to parse Android bootloader (aboot) images, extract certificates and verify image signature.

May not work on aboot from latest devices. Signature verification follows the 
'Secure Boot and Image Authentication Technical Overview' whitepaper by Qualcomm.
Cf. https://www.qualcomm.com/documents/secure-boot-and-image-authentication-technical-overview

aboot header format as described in http://newandroidbook.com/Articles/aboot.html
See above article for more details about aboot. 

Inspired by https://github.com/kayrus/kc_s701_break_free

Tested on aboot from
 * Nexus 5
 * Kyocera Brigadier 
 * Kyocera KC-S701

Usage:

```
$ ./parse-aboot.py n5-aboot.img 
aboot image n5-aboot.img, len=339180
aboot header:
----------------------------------------
magic:             0x00000005
version:           0x00000003
NULL:              0x00000000
ImgBase:           0x0f900000
ImgSize:           0x00052cc4 (339140)
CodeSize:          0x000513c4 (332740)
ImgBaseCodeSize:   0x0f9513c4
SigSize:           0x00000100 (256)
CodeSigOffset:     0x0f9514c4
Certs size:        0x00001800 (6144)

SigOffset:         0x000513ec

Dumping all certificates...
cert 1: cert-1.cer, size: 1186
cert 2: cert-2.cer, size: 1025
cert 3: cert-3.cer, size:  922
Total cert size:          3133

Trying to calculate image hash...
Expected: c8f94b5762b14439647192d82501331093c079154a379048e2d9ef3166d7587b (32)
My hash:  c8f94b5762b14439647192d82501331093c079154a379048e2d9ef3166d7587b (32)
Hashes match
```


