#!/usr/bin/env python3

from uefi_firmware.uefi import *
import hashlib
#from OpenSSL import crypto
import M2Crypto
import pyasn1.codec.der.decoder as asn1dec
from pyasn1_modules import rfc2315
import pyasn1
import base64

from Crypto.PublicKey import RSA

#import pprint
import texttable as tt

EFI_FFS_FILE_HEADER_SIZE=24

def check_firmware_sig(fname):
    fp = open(fname, 'rb')
    data = fp.read()

    # process all firmware volumes
    volume_indices = search_firmware_volumes (data)
    firmware_volume_list=[]
    for index in volume_indices:
        print("volume at index 0x%08x 0x%08x"%(index, index-40))
        datastart = data[index-40:]
        name = index-40
        firmware_volume = FirmwareVolume(datastart, name)
        firmware_volume.process()
        firmware_volume_list.append(firmware_volume)

    # find the firmware file marked by a special GUID: we are looking for the signature table.
    guid='414D94AD-998D-47D2-BFCD-4E882241DE32'
    offset, length = find_guid_offset (firmware_volume_list, guid)
    if not offset: exit(1)
    print('--> sigtable guid %s found offset=0x%x size=%d'%(guid, offset, length))

    # extract and dump the signature table
    table = extract_sig_table (data, offset, length)
    tab = tt.Texttable()
    tab.header(('Address', 'length', 'signed'))
    for entry in table:
        tab.add_row(("0x%08x"%(entry[0]), entry[1], entry[2]))
    print("Signature table")
    print("===============")
    print(tab.draw())
    print()

    # collect the digest of all signed regions.
    digest=collect_signeddata (data, table)
    print("============")
    print("| Digest   |")
    print("============")
    print("%s"%(digest))
    print()
    
    # extract the public key
    pkcert_guid='3A666558-43E3-4D25-9169-DB81F5DB42E1'
    pkcert_offset, pkcert_length = find_guid_offset(firmware_volume_list, pkcert_guid)
    if not pkcert_offset: exit(1)
    print('--> pkcert guid %s found offset=0x%x size=%d'%(pkcert_guid, pkcert_offset, pkcert_length))
    pkcert, rsakey = m2crypto_extract_cert_pubkey (data, pkcert_offset, pkcert_length)

    print("--> pkcert extracted, signer=%s"%(pkcert.get_issuer()))

    # extract the signed digest
    print("\nDigital Signature")
    print("===================")
    cert=extract_signed_digest(data, offset, length)
    print(cert)
#    print("--> pkcs7 extracted, is_signed = %d is_data=%d"%(signedkey.type_is_signed(), signedkey.type_is_data()))

    # load the certificate
    #s = M2Crypto.SMIME.SMIME()
    #sk = M2Crypto.X509.X509_Stack()
    #sk.push(pkcert)
    #s.set_x509_stack(sk)

    # load the pkcs7 data
    #p7, data
    
#    pkcs7 = M2Crypto.SMIME.PKCS7(signedkey, 1)
#    pkcs7.get0_signers(M2Crypto.X509.X509_Stack())
    

    return
        
# #########################################################
# find the offset in the binary file of a particular firmware
# file marked by a particular GUID.
# #########################################################

def find_guid_offset (firmware_volume_list, guid):
    for firmware_volume in firmware_volume_list:
        dict = firmware_volume.to_dict()
        for ff in dict['ffs']:
            if ff['guid'].lower() == guid.lower():
                return (ff['offset'], ff['size'])
    return (None, None)

# #########################################################
# given the offset of a particular firmware file, extract
# the undocumented list of all signed regions
# #########################################################

def extract_sig_table (data, offset, length):
    table=[]
    start_offset = offset + 0xef4
    off1 = start_offset
    table_length=0
    while True:
        fun, zeros, first, leng, flag2, flag1 = struct.unpack('<LLLLLL', data[off1:off1+24])
        #print("first={:08x} len={:10d} f={} flag={:08x}".format(first, leng, (flag1>>9)&1 ,flag1))
        if flag1 == 0 and leng == 0 and first == 0 :
            break
        table.append((first+0x1000000, leng, ((flag1>>9)&1)))
        off1 += 24
        table_length += 24
    # the last entry is for the table itself.
    table.append((start_offset, table_length+24, True))    
    return table


# #########################################################
# extract the signed digest of a firmware file
# #########################################################

def extract_signed_digest(data, offset, length):
    # skip over 116 bytes (?)
    offset+=116

    # check that the capsule GUID is what we want it to be.
    # then skip past the capsule header + 4 bytes of padding
    print(unpack_guid(data[offset:]))
    offset+=32

    # WIN_CERTIFICATE header
    wc_dwlen, wc_wrev, wc_type= struct.unpack('<LHH', data[offset:offset+8])
    #print("dwlen=%d"%(wc_dwlen))
    offset+=8

    # wincert GUID
    #print("wincert guid=%s"%(unpack_guid(data[offset+8:])))
    offset+=16
    
    # actual certificate starts here.
    # however, there is a 24 byte ASN1 "fudge" we have to skip over
    fudge=24
    offset += 8+16

    # start parsing the certificate
    seq, remain = asn1dec.decode(data[offset:offset+wc_dwlen-24-fudge], asn1Spec=rfc2315.ContentInfo())
    print(seq)
    # the envelope is a sequence
#    if type(seq) != pyasn1.type.univ.SequenceOf:
#        exit(1)
#    print(seq.componentType)
#    print(seq.getComponentByPosition(0))
#    c = asn1dec.decode(c)
#    if type(t) != pyasn1.type.univ.SequenceOf: exit(1)
#    t,c = asn1dec.decode(c)    
    
    exit(0)
    
    #asn1crypto.Certificate.load(data[offset:offset+wc_dwlen-24-fudge])
    
    #cert=crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, data[offset:offset+wc_dwlen-24-fudge])
    #return cert
    
    #p7, bio=M2Crypto.SMIME.smime_load_pkcs7_bio(M2Crypto.BIO.MemoryBuffer(data[offset:offset+wc_dwlen-24-fudge]))
    #return p7, bio

def m2crypto_extract_cert_pubkey (data, offset, length):
    offset += 100
    pkcert=M2Crypto.X509.load_cert_string(data[offset:offset+length], M2Crypto.X509.FORMAT_DER)
    pubkey=pkcert.get_pubkey()
    rsakey=pubkey.get_rsa()
    return (pkcert, rsakey)


def crypto_extract_cert (data, offset, length):
    True


# #########################################################
# collect the sha256 digest using the signed data table.
# #########################################################

def collect_signeddata (data, table):
    signedlen=0
    unsignedlen=0
    m=hashlib.sha256()
    body=b''
    for entry in table:
        offset=entry[0]
        length=entry[1]
        flag=entry[2]
        if flag == 1:
            #print("collecting offset=0x%08x length=%d"%(offset, length))
            m.update(data[offset:offset+length])
            body += data[offset:offset+length]
            signedlen += length
        else:
            unsignedlen += length
    fp=open('body.bin', 'wb')
    fp.write(body)
    fp.close()
    return m.hexdigest()
    




def unpack_guid (data):
    w1=struct.unpack('<LHH',data[:8])
    w2=struct.unpack('>H',data[8:10])
    w3=struct.unpack('>LH',data[10:16])
    return '{0:08x}-{1:04x}-{2:04x}-{3:04x}-{4:08x}{5:04x}'.format(w1[0], w1[1], w1[2], w2[0], w3[0], w3[1])





check_firmware_sig('/home/galmasi/code/firmware/supermicro/IBM_X11QPH_20211018_storage.ROM')
#check_firmware_sig('/home/galmasi/repo/cloud-infrastructure/xCAT_Scripts/install/firmware/smc/Softlayer_X11QPH_20200805.ROM_Signed')
#check_firmware_sig('/home/galmasi/code/firmware/supermicro/IBM_X11QPH_20211022_compute.ROM')





