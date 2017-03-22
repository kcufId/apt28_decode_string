# apt28 2016-10_ESET_Sednit Approaching the Target
# md5: 9863F1EFC5274B3D449B5B7467819D28
# idc ask input size, then decode one section.
# This py will decode all data at a time.by xref.

import idc
import idautils
import idaapi

decode_proc = 0x10003EA1
#key  0x10007B20 
#key = []
def xor_data(addr, size):
    key_address = 0x10007B20
    string = ''
    #key_size = 0xB
    uIndex = 0
    for i in xrange(size):
        value = idc.Byte(addr+i)
        uIndex = i % 0xB
        key_value = Byte(key_address+uIndex)
        #value ^= key_value
        string  += chr(value ^ key_value)
    print '[+] decode string: ', string
    return string

for addr in idautils.CodeRefsTo(decode_proc, 0):
    #search push 
    temp = addr
    crypt_data = 0
    crypt_size = 0
    print '[+] call function: %#x ' % addr
    for x in xrange(1, 6):
        prev_addr = idc.PrevHead(temp)
        m = idc.GetMnem(prev_addr)
        if m == 'push' and idc.GetOpType(prev_addr, 0) == 5:        # shield: push esi push edi
            delta = temp - prev_addr
            if delta == 5:
                valrr = idc.Dword(idc.NextAddr(prev_addr))
                if valrr < 0x20000000:
                    crypt_data = valrr
            else:
                crypt_size = idc.Byte(idc.NextAddr(prev_addr))
        if m == 'add':
            print 'Exist add %#x' % prev_addr

        temp = prev_addr
    if crypt_data != 0 and crypt_size != 0:
        print '[+] Decode data address %#x size: %#x' % (crypt_data, crypt_size)

        comment = xor_data(crypt_data, crypt_size)
        idc.MakeComm(crypt_data, comment)
    else:
        print '[-] Error'
    
print '[+] ok!'



                



            
