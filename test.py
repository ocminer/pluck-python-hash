def _test():
    import binascii
    import pluck_hash       
        
    header_bin = binascii.unhexlify('0000000356a4f0b51f5d96121f0057c01031641c0bba0ee99d82666cbea2179c00003ca5be3cd8ecf3110a1e887e08e1c56d02e37794bad5fb3d403954e606c6715e0bb854e483641e5c224740000423')

    hash_bin = pluck_hash.getPoWHash(''.join([ header_bin[i*4:i*4+4][::-1] for i in range(0, 20) ]))
    block_hash_hex = hash_bin[::-1].encode('hex_codec')
    print block_hash_hex # 000516d5ef5fb1323a812abd9123fec4a17cbf5d31564f441948a75f0121999b

if __name__ == '__main__':
    _test()
