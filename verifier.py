#!/usr/bin/env python3

from uefi_firmware.uefi import *
import hashlib
from OpenSSL import crypto
import M2Crypto


def check_firmware_sig(fname):
    fp = open(fname, 'rb')
    data = fp.read()

    # process all firmware volumes
    volume_indices = search_firmware_volumes (data)
    firmware_volume_list=[]
    for index in volume_indices:
        print("volume at index 0x%8x"%(index))
        datastart = data[index-40:]
        name = index-40
        firmware_volume = FirmwareVolume(datastart, name)
        firmware_volume.process()
        firmware_volume_list.append(firmware_volume)

    # find the firmware file marked by a special GUID
    guid='414D94AD-998D-47D2-BFCD-4E882241DE32'
    offset, length = find_guid_offset (firmware_volume_list, guid)
    if not offset: exit(1)
    print('--> sigtable guid %s found offset=0x%x size=%d'%(guid, offset, length))

    # extract the (undocumented) signature table
    table = extract_sig_table (data, offset, length)

    print("Sigtable")
    print("=====================")
    for entry in table:
        print("off=0x%08x end=0x%08x flag=%d"%(entry[0], entry[0]+entry[1], entry[2]))
    print()

    # extract the signed digest
    signedkey = extract_signed_digest(data, offset, length)
    print("pkcs7 key extracted, is_signed = %d is_data=%d"%(signedkey.type_is_signed(), signedkey.type_is_data()))

    # extract the public key
    pk_guid='3A666558-43E3-4D25-9169-DB81F5DB42E1'
    pk_offset, pk_length = find_guid_offset(firmware_volume_list, pk_guid)
    if not pk_offset: exit(1)
    print('--> pubkey guid %s found offset=0x%x size=%d'%(pk_guid, pk_offset, pk_length))
    pkcert = extract_pk (data, pk_offset, pk_length)
    print("pkcert extracted, signer=%s"%(pkcert.get_issuer()))
    pk=pkcert.get_pubkey()
    print(pk)
    

    #    MCrypto.RSA.load_key_string

    
    #cipher=PKCS1_OAEP.new(pk)

    #crypto._lib.RSA_public_decrypt

    # M2Crypto.RSA.RSA.public_decrypt
    
    # bla
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
    for off1 in range(0xef4,length, 24):
        try:
            _, _, off2, len2, flag2, _ = struct.unpack('<LLLLLL', data[offset+off1:offset+off1+24])
            if off1 == 0: break
        except:
            break
        table.append((off2, len2, flag2))
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
    print("dwlen=%d"%(wc_dwlen))
    offset+=8

    # wincert GUID
    print("wincert guid=%s"%(unpack_guid(data[offset+8:])))
    offset+=16
    
    # actual certificate starts here.
    # however, there is a 24 byte ASN1 "fudge" we have to skip over
    fudge=24
    offset += 8+16

    # the actual certificate
    cert=crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, data[offset:offset+wc_dwlen-24-fudge])
    return cert

def extract_pk(data, offset, length):
    offset += 100
    return crypto.load_certificate(crypto.FILETYPE_ASN1, data[offset:offset+length])
    





#        dict = firmware_volume.to_dict()
#        for ff in dict['ffs']:
#            if ff['guid'] == '414D94AD-998D-47D2-BFCD-4E882241DE32'.lower():
#                print(ff)
#                startoffset=ff['offset']
#                endoffset=ff['offset']+ff['size']
#                body=data[startoffset:endoffset]
#                table=extract_offset_table(body)

#    m1=hashlib.sha256()
#    m2=hashlib.sha256()
#    m3=hashlib.sha256()
#    for entry in table:
#        start = entry[0]
#        end = entry[0]+entry[1]
#        print("off=0x%08x end=0x%08x flag=%d"%(start, end, entry[2]))
#        m1.update(data[start:end])
#        if  entry[2] == 1: m2.update(data[start:end])
#        if  entry[2] == 0: m3.update(data[start:end])

#    print(m1.hexdigest())
#    print(m2.hexdigest())
#    print(m3.hexdigest())



def unpack_guid (data):
    w1=struct.unpack('<LHH',data[:8])
    w2=struct.unpack('>H',data[8:10])
    w3=struct.unpack('>LH',data[10:16])
    return '{0:08x}-{1:04x}-{2:04x}-{3:04x}-{4:08x}{5:04x}'.format(w1[0], w1[1], w1[2], w2[0], w3[0], w3[1])





check_firmware_sig('IBM_X11QPH_20211018_storage.ROM')





