#!/usr/bin/env python3

from uefi_firmware.uefi import *
import base64
import hashlib
import M2Crypto
import pyasn1
import pyasn1.codec.der.decoder as asn1dec
from pyasn1_modules import rfc2315, rfc4055

EFI_FFS_FILE_HEADER_SIZE=24

def check_firmware_sig(fname):
    fp = open(fname, 'rb')
    data = fp.read()

    # ###################################################
    # process all firmware volumes
    # ###################################################

    volume_indices = search_firmware_volumes (data)
    firmware_volume_list=[]
    for index in volume_indices:
        print("Found firmware volume at index 0x%08x 0x%08x"%(index, index-40))
        datastart = data[index-40:]
        name = index-40
        firmware_volume = FirmwareVolume(datastart, name)
        firmware_volume.process()
        firmware_volume_list.append(firmware_volume)

    # ###################################################
    # find the firmware file marked by a special GUID:
    # we are looking for the signature table.
    # ###################################################

    sig_guid='414D94AD-998D-47D2-BFCD-4E882241DE32'
    sig_offset, sig_length = find_guid_offset (firmware_volume_list, sig_guid)
    if not sig_offset: exit(1)
    print('+-------------------------------------------+-------------------+-----------------+')
    print('| guid %36s | offset=0x%08x | size=%10d |'%(sig_guid, sig_offset, sig_length))
    print('+-------------------------------------------+-------------------+-----------------+')
    print()

    # ###################################################
    # extract and dump the signature table
    # ###################################################

    table = extract_sig_table (data, sig_offset, sig_length)
    print("+------------------------------+")
    print("|     Signature table          |")
    print("+----------+----------+--------+")
    print("| address  |  length  | signed |")
    print("+----------+----------+--------+")
    for entry in table:
        print("|0x%08x|%10d|%8d|"%(entry[0], entry[1], entry[2]))
    print("+----------+----------+--------+")
    print()

    # ###################################################
    # collect the digest of all signed regions.
    # ###################################################

    digest=collect_signeddata (data, table)
    print("+--------+" + '-'*64 + '+')
    print("| Digest |%64s|"%(digest.hex()))
    print("+--------+" + '-'*64 + '+')
    print()
    
    # ###################################################
    # extract the signed digest
    # ###################################################

    sigbody=extract_sig(data, sig_offset, sig_length)
    print('+-------------------+')
    print('| Digital Signature |')
    print('+-------------------+')
    print(sigbody.hex())
    print()

    # extract the public key
    pkcert_guid='3A666558-43E3-4D25-9169-DB81F5DB42E1'
    pkcert_offset, pkcert_length = find_guid_offset(firmware_volume_list, pkcert_guid)
    if not pkcert_offset: exit(1)
    print('+-------------------------------------------+-------------------+-----------------+')
    print('| guid %36s | offset=0x%08x | size=%10d |'%(pkcert_guid, pkcert_offset, pkcert_length))
    print('+-------------------------------------------+-------------------+-----------------+')
    pkcert, rsakey = extract_cert_pubkey (data, pkcert_offset, pkcert_length)
    print("--> pkcert extracted, signer=%s"%(pkcert.get_issuer()))
    

    vstatus=rsakey.verify(digest, sigbody, 'sha256')
    print('+------------------------+')
    print('| Verification status: %1d |'%(vstatus))
    print('+------------------------+')
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

def extract_sig(data, offset, length):
    # skip over 116 bytes (?)
    offset+=116

    # check that the capsule GUID is what we want it to be.
    # then skip past the capsule header + 4 bytes of padding
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
    substrate=data[offset:offset+wc_dwlen-24-fudge]

    # the first component is the pkcs7-data marker.
    b1, remain1 = asn1dec.decode(substrate, asn1Spec=rfc2315.ContentInfo())
    contenttype = b1.getComponentByName('contentType')
    assert contenttype == (1, 2, 840, 113549, 1, 7, 1)

    # the second component is a sequence with signature metadata
    b2, remain2 = asn1dec.decode(remain1)
    assert type(b2) == pyasn1.type.univ.Sequence
    
    # the third component is a set containing a sequence
    # the 5th component of the sequence is the 256 byte RSA encrypted sig.
    b3, remain3 = asn1dec.decode(remain2)
    assert type(b3) == pyasn1.type.univ.SetOf
    b31 = b3.getComponentByPosition(0)
    assert type(b31) == pyasn1.type.univ.Sequence
    b314 = b31.getComponentByPosition(4)
    assert type(b314) == pyasn1.type.univ.OctetString
    assert len(b314) == 256
    return bytes(b314)

# #########################################################
# #########################################################

def extract_cert_pubkey (data, offset, length):
    offset += 100
    pkcert=M2Crypto.X509.load_cert_string(data[offset:offset+length], M2Crypto.X509.FORMAT_DER)
    pubkey=pkcert.get_pubkey()
    rsakey=pubkey.get_rsa()
    return (pkcert, rsakey)


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
    return m.digest()

# #########################################################
# #########################################################

def unpack_guid (data):
    w1=struct.unpack('<LHH',data[:8])
    w2=struct.unpack('>H',data[8:10])
    w3=struct.unpack('>LH',data[10:16])
    return '{0:08x}-{1:04x}-{2:04x}-{3:04x}-{4:08x}{5:04x}'.format(w1[0], w1[1], w1[2], w2[0], w3[0], w3[1])



# #########################################################
# #########################################################

check_firmware_sig('/home/galmasi/code/firmware/supermicro/IBM_X11QPH_20211018_storage.ROM')
#check_firmware_sig('/home/galmasi/repo/cloud-infrastructure/xCAT_Scripts/install/firmware/smc/Softlayer_X11QPH_20200805.ROM_Signed')
#check_firmware_sig('/home/galmasi/code/firmware/supermicro/IBM_X11QPH_20211022_compute.ROM')





