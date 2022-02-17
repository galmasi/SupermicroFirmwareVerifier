#!/usr/bin/env python3

from uefi_firmware.uefi import *
import hashlib
from OpenSSL import crypto
#import M2Crypto
import base64


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

    # find the firmware file marked by a special GUID
    guid='414D94AD-998D-47D2-BFCD-4E882241DE32'
    offset, length = find_guid_offset (firmware_volume_list, guid)
    if not offset: exit(1)
    print('--> sigtable guid %s found offset=0x%x size=%d'%(guid, offset, length))

    # extract the (undocumented) signature table
    table = extract_sig_table (data, offset, length)

    print("\nSigtable")
    print("=====================")
    for entry in table:
        print("off=0x%08x end=0x%08x len=%10d flag=%d"%(entry[0], entry[0]+entry[1], entry[1], entry[2]))
    print()

    #additional_unsigneds(data, firmware_volume_list)
    
    # extract the signed digest
    #print("\nDigital Signature")
    #print("===================")
    #signedkey =
    #extract_signed_digest(data, offset, length)
    #print("--> pkcs7 extracted, is_signed = %d is_data=%d"%(signedkey.type_is_signed(), signedkey.type_is_data()))



    # extract the public key
    #pkcert_guid='3A666558-43E3-4D25-9169-DB81F5DB42E1'
    #pkcert_offset, pkcert_length = find_guid_offset(firmware_volume_list, pkcert_guid)
    #if not pkcert_offset: exit(1)
    #print('--> pkcert guid %s found offset=0x%x size=%d'%(pkcert_guid, pkcert_offset, pkcert_length))
    #pkcert, pubkey = m2crypto_extract_cert (data, pkcert_offset, pkcert_length)
    #print("--> pkcert extracted, signer=%s"%(pkcert.get_issuer()))
    #print("TODO: extract digest from signature")

    # load the certificate
    #s = M2Crypto.SMIME.SMIME()
    #sk = M2Crypto.X509.X509_Stack()
    #sk.push(pkcert)
    #s.set_x509_stack(sk)

    # load the pkcs7 data
    #p7, data
    
#    pkcs7 = M2Crypto.SMIME.PKCS7(signedkey, 1)
#    pkcs7.get0_signers(M2Crypto.X509.X509_Stack())
    



    

    signedbody, len, digest = collect_signeddata (data, table)
    print("\nDigest")
    print("============")
    print("digest for signed part = %s"%(digest))


    digest2=collect_signeddata2(data, table)
    print ("alternative computation=%s"%(digest2))

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
        fun, zeros, first, leng, flag2, bla = struct.unpack('<LLLLLL', data[off1:off1+24])
        print("first={:08x} len={:10d} f={} flag={:08x}".format(first, leng, (bla>>9)&1 ,bla))
        if bla == 0 and leng == 0 and first == 0 :
            break
        table.append((first+0x1000000, leng, ((bla>>9)&1)))
        off1 += 24
        table_length += 24

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

    # the actual certificate
    #cert=crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, data[offset:offset+wc_dwlen-24-fudge])
    #return cert
    
    p7, bio=M2Crypto.SMIME.smime_load_pkcs7_bio(M2Crypto.BIO.MemoryBuffer(data[offset:offset+wc_dwlen-24-fudge]))
    return p7, bio

def m2crypto_extract_cert (data, offset, length):
    offset += 100
    pkcert=M2Crypto.X509.load_cert_string(data[offset:offset+length], M2Crypto.X509.FORMAT_DER)
    return (pkcert, pkcert.get_pubkey())


# #########################################################
# #########################################################

def collect_signeddata(data, table):
    body=b''
    newlen=0
    for entry in table:
        offset=entry[0]
        length=entry[1]
        flag=entry[2]
        if flag == 1:
            print("collecting offset=0x%08x length=%d"%(offset, length))
            body += data[offset:offset+length]
            newlen += length
    m=hashlib.sha256()
    m.update(body)
    return ( body, newlen, m.hexdigest() )

# #########################################################
# collect the sha256 digest using the signed data table.
# #########################################################

def collect_signeddata2(data, table):
    signedlen=0
    unsignedlen=0
    m=hashlib.sha256()
    for entry in table:
        offset=entry[0]
        length=entry[1]
        flag=entry[2]
        if flag == 1:
            print("collecting offset=0x%08x length=%d"%(offset, length))
            m.update(data[offset:offset+length])
            signedlen += length
        else:
            unsignedlen += length
            
    print("signed length=%d unsigned length=%d total=%d    %d"%(signedlen, unsignedlen, signedlen+unsignedlen, len(data)))
    return m.hexdigest()
    


def additional_unsigneds (data, firmware_volume_list):
    print("additional unsigned regions worklist")
    print("==============================")

    # OA2
    # As with all firmware modules, the GUID is the Name in an EFI_FFS_FILE_HEADER struct.
    # The entire module is unsigned except for the header, so the size of the unsigned
    # region can be calculated with Size[3] ? sizeof(EFI_FFS_FILE_HEADER).

    guid='69009842-63F2-43DB-964B-EFAD1C39EC85'
    offset, length = find_guid_offset (firmware_volume_list, guid)
    offset += EFI_FFS_FILE_HEADER_SIZE
    length -= EFI_FFS_FILE_HEADER_SIZE
    print("OA2 0x%08x, 0x%08x %d"%(offset, offset+length, length))

    # OA2
    # As with all firmware modules, the GUID is the Name in an EFI_FFS_FILE_HEADER struct.
    # The entire module is unsigned except for the header, so the size of the unsigned
    # region can be calculated with Size[3] ? sizeof(EFI_FFS_FILE_HEADER).

    guid='996AA1E0-1E8C-4F36-B519-A170A206FC14'
    offset, length = find_guid_offset (firmware_volume_list, guid) 
    offset += EFI_FFS_FILE_HEADER_SIZE
    length -= EFI_FFS_FILE_HEADER_SIZE
    print("OA2 0x%08x, 0x%08x %d"%(offset, offset+length, length))
    
    # OA3

    guid='3FD1D3A2-99F7-420b-BC69-8BB1D492A332'
    offset, length = find_guid_offset (firmware_volume_list, guid)
    # skip over the header
    for off1 in range(offset, offset+length, 4):
        val=struct.unpack('4s',data[off1:off1+4])
        if val[0] == b'$FID':
            #print("off1=%x"%(off1))
            break
    print("OA3 0x%08x, 0x%08x %d"%(off1, offset+49, 49))
    
    
    # signature
            
    guid='414D94AD-998D-47D2-BFCD-4E882241DE32'
    offset, length = find_guid_offset (firmware_volume_list, guid) 
    offset+=116
#   print(unpack_guid(data[offset:]))
    offset+=30
    newlen=struct.unpack('<H',data[offset:offset+2])
#   print(newlen[0])
    print("sig 0x%08x, 0x%08x %d <---- TODO"%(offset, offset+newlen[0], newlen[0]))
    
    return




def unpack_guid (data):
    w1=struct.unpack('<LHH',data[:8])
    w2=struct.unpack('>H',data[8:10])
    w3=struct.unpack('>LH',data[10:16])
    return '{0:08x}-{1:04x}-{2:04x}-{3:04x}-{4:08x}{5:04x}'.format(w1[0], w1[1], w1[2], w2[0], w3[0], w3[1])





check_firmware_sig('/home/galmasi/code/firmware/supermicro/IBM_X11QPH_20211018_storage.ROM')
#check_firmware_sig('/home/galmasi/repo/cloud-infrastructure/xCAT_Scripts/install/firmware/smc/Softlayer_X11QPH_20200805.ROM_Signed')
#check_firmware_sig('/home/galmasi/code/firmware/supermicro/IBM_X11QPH_20211022_compute.ROM')





