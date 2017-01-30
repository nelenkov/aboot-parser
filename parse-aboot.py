#!/usr/bin/env python

import struct
import sys
import os
import hashlib
import binascii

from pyasn1_modules import  rfc2437,rfc2459
from pyasn1.codec.der import decoder

import rsa
from rsa import common, transform, core

ABOOT_HEADER_LEN = 40

class AbootHeader:
    def parse(self, aboot):
        (magic, version, null, img_base, img_size, code_size, img_base_code_size, sig_size, code_sig_offset, cert_size) = struct.unpack('< 10I', aboot[0:ABOOT_HEADER_LEN])
        self.magic = magic
        self.version = version
        self.null = null
        self.img_base = img_base
        self.img_size = img_size
        self.code_size = code_size  
        self.img_base_code_size = img_base_code_size
        self.sig_size = sig_size
        self.code_sig_offset = code_sig_offset
        self.cert_size = cert_size

    def dump(self):
        print 'aboot header:'
        print '-' * 40
        print 'magic:             0x%08x' % self.magic
        print 'version:           0x%08x' % self.version
        print 'NULL:              0x%08x' % self.null
        print 'ImgBase:           0x%08x' % self.img_base
        print 'ImgSize:           0x%08x (%d)' % (self.img_size, self.img_size)
        print 'CodeSize:          0x%08x (%d)' % (self.code_size, self.code_size)
        print 'ImgBaseCodeSize:   0x%08x' % self.img_base_code_size 
        #print 'ImgBaseCodeSize:   0x%08x' % (img_base + code_size)
        print 'SigSize:           0x%08x (%d)' % (self.sig_size, self.sig_size)
        print 'CodeSigOffset:     0x%08x' % self.code_sig_offset
        print 'Certs size:        0x%08x (%d)' % (self.cert_size, self.cert_size)
        print

    def sig_offset(self):
        return ABOOT_HEADER_LEN + header.code_size

    def cert_offset(self):
        return self.sig_offset()  + self.sig_size

def dump_signature(aboot, header, filename):
    sig_offset = header.sig_offset()
    print 'SigOffset:         0x%08x' % sig_offset
    print 

    fmt = '< %ds' % header.sig_size
    sig = struct.unpack(fmt, aboot[sig_offset:sig_offset + header.sig_size])[0]
    with open(filename, 'wb') as f:
        f.write(sig)

    return sig

def frombits(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)

# only the bits we need. 
# Cf. https://www.qualcomm.com/documents/secure-boot-and-image-authentication-technical-overview
#OU=07 0001 SHA256
#OU=06 00XX MODEL_ID
#OU=05 0000XXXX SW_SIZE
#OU=04 00XX OEM_ID
#OU=03 0000000000000002 DEBUG
#OU=02 00XXXXXXXXXXXXXX HW_ID
#OU=01 000000000000000X SW_ID
class CertInfo:
    device_ids = []     
    pub_key = None
    cert_len = 0

    def get_id(self, id_name):
        if not self.device_ids:
            return None

        for di in self.device_ids:
            if id_name in di:
                return binascii.unhexlify(di.split(' ')[1])

        return None

    def get_sw_id(self):
        return self.get_id('SW_ID')

    def get_hw_id(self):
        return self.get_id('HW_ID')

def parse_cert(raw_bytes):
    result = CertInfo()

    certType = rfc2459.Certificate(); 
    cert, rest = decoder.decode(raw_bytes, asn1Spec=certType)
    subj_pub_key_bytes = frombits(cert.getComponentByName('tbsCertificate').getComponentByName('subjectPublicKeyInfo').getComponentByName('subjectPublicKey'))
    SUBJECT = cert.getComponentByName('tbsCertificate').getComponentByName('subject')
    for rdn in SUBJECT[0]:
        for nv in rdn: 
            name = nv.getComponentByName('type')
            value = nv.getComponentByName('value')
            if name == rfc2459.id_at_organizationalUnitName and ('_ID' in str(value)):
                #print 'name: %s' % name
                #print 'value: [%s] (%s)' % (str(value).strip(), type(value))
                result.device_ids.append(str(value).strip())

    rsaType = rfc2437.RSAPublicKey();
    rsadata,rsadata_rest = decoder.decode(subj_pub_key_bytes, asn1Spec=rsaType)
    mod = rsadata.getComponentByName("modulus")
    pub_exp = rsadata.getComponentByName("publicExponent")
    result.pub_key = rsa.PublicKey(long(mod), long(pub_exp))

    return result

def dump_cert(aboot, cert_offset, filename):
    # DIY ASN.1
    if aboot[cert_offset] == '\x30' and aboot[cert_offset + 1] == '\x82':
        seq_len = struct.unpack('> H', aboot[cert_offset + 2:cert_offset + 4])[0]
        cert_len = seq_len + 4

        fmt = '< %ds' % cert_len
        cert = struct.unpack(fmt, aboot[cert_offset:cert_offset + cert_len])[0]
        with open(filename, 'wb') as f:
            f.write(cert)
        cert_info = parse_cert(cert)
        cert_info.cert_len = cert_len

        return cert_info
    else:
        return None

def xor(key, pad):
    result = bytearray(len(key))
    result[:] = key[:]

    p = bytearray(len(pad))
    p[:] = pad[:]

    for i in xrange(len(p)):
        result[i] ^= p[i]

    return str(result)

def calc_hash(aboot_base, hw_id, sw_id):
    o_pad = '\x5c' * 8
    i_pad = '\x36' * 8

    h0 = hashlib.sha256(aboot_base).digest()
    #print 'H0:         %s' % h0.encode('hex')

    sw_id_ipad = xor(sw_id, i_pad)
    #print 'sw_id_ipad: %s' % sw_id_ipad.encode('hex')
    hw_id_opad = xor(hw_id, o_pad)
    #print 'hw_id_opad: %s' % hw_id_opad.encode('hex')

    m1 = bytearray(len(sw_id_ipad) + len(h0))
    m1[0:len(sw_id_ipad)] = sw_id_ipad[:]
    m1[len(sw_id_ipad):] = h0[:]
    #print 'M1:         %s' % str(m1).encode('hex')
    h1 = hashlib.sha256(m1).digest()
    #print 'H1:         %s' % h1.encode('hex')

    m2 = bytearray(len(hw_id_opad) + len(h1))
    m2[0:len(hw_id_opad)] = hw_id_opad[:]
    m2[len(hw_id_opad):] = h1[:]
    #print 'M2:         %s' % str(m2).encode('hex')
    h2 = hashlib.sha256(m2).digest()
    #print 'H2:         %s (%d)' % (h2.encode('hex'), len(h2))

    return h2

def extract_raw_hash(signature, pub_key):
    keylength = common.byte_size(pub_key.n)
    encrypted = transform.bytes2int(signature)
    decrypted = core.decrypt_int(encrypted, pub_key.e, pub_key.n)
    clearsig = transform.int2bytes(decrypted, keylength)
    # unpad
    raw_hash_idx = clearsig.find('\x00', 2) + 1

    return clearsig[raw_hash_idx:]

def dump_all_certs(aboot, header, base_filename):
    cert_infos = []
    cert_offset = header.cert_offset()

    cert_num = 1
    cert_size = 0
    print 'Dumping all certificates...'
    while cert_offset < len(aboot):
        #print 'CertOffset:        0x%08x' % cert_offset
        filename = '%s-%d.cer' % (base_filename, cert_num)
        cert_info = dump_cert(aboot, cert_offset, filename)
        if (cert_info is None):
            break

        print 'cert %d: %s, size: %4d' % (cert_num, filename, cert_info.cert_len)
        #print 'pub key: %s' % pub_key 
        cert_infos.append(cert_info)

        cert_num += 1
        cert_offset = cert_offset + cert_info.cert_len
        cert_size += cert_info.cert_len

    print     'Total cert size         : %4d' % cert_size
    print

    return cert_infos

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage: %s aboot.img' % sys.argv[0]
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
       aboot = bytes(f.read())
    print 'aboot image %s, len=%d' % (sys.argv[1], len(aboot))
    
    header = AbootHeader()
    header.parse(aboot)
    header.dump()

    sig = dump_signature(aboot, header, 'signature.bin')

    cert_infos = dump_all_certs(aboot, header, 'cert')

    # assume [0] is leaf/signing cert
    expected_hash = extract_raw_hash(sig, cert_infos[0].pub_key)
    #print 'expected_hash %s' % expected_hash.encode('hex')
            
    print 'Trying to calculate image hash...'
    hw_id = cert_infos[0].get_hw_id()
    sw_id = cert_infos[0].get_sw_id()
    if hw_id is None or sw_id is None:
        raise Exception('Could not find HW_ID or SW_ID')

    # both header and code are signed
    aboot_sig_target = aboot[0:ABOOT_HEADER_LEN + header.code_size]
    my_hash = calc_hash(aboot_sig_target, hw_id, sw_id)

    print 'Expected: %s (%d)' % (expected_hash.encode('hex'), len(expected_hash))
    print 'My hash:  %s (%d)' % (my_hash.encode('hex'), len(my_hash))
    if my_hash == expected_hash:
        print 'Hashes match'
    else:
        print 'Hashes don\'t match'


