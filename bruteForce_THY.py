from sys import argv
from datetime import datetime
S_box_inv = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
)

class welcome:
    def welcoming_banner():
        print(""" _____  _   _ __   __   ____  _         _
|_   _|| | | |\ \ / /  / ___|(_) _ __  | |__    ___  _ __
  | |  | |_| | \ V /  | |    | || '_ \ | '_ \  / _ \| '__|
  | |  |  _  |  | |   | |___ | || |_) || | | ||  __/| |
  |_|  |_| |_|  |_|    \____||_|| .__/ |_| |_| \___||_|
                                |_|""")
        print("-_-"*20,"\n")

    def banner():
        print('''       ,
      /(  ___________
     |  >:===========`
      )(  
  BruteForcing....\n''')


class decryption:
    def if_no_8_bytes(Bytes): # we call this function if the last block is not 8 bytes long
        n=8-len(Bytes)%8
        null_added=n*'\x00' 
        null_added=bytes(null_added,'utf-8')
        # adding a null byte so it doesn't affect the file, also making the last block = 8 bytes long
        return Bytes + null_added

    def deviding_block(raw,key):
        plain_text=b''
        raw=raw[::-1] # reversing file contents
        for i in range(0,len(raw),8): # deviding raw data as 8 bytes block
            
            Bytes=raw[i:i+8]
            if len(Bytes)%8!=0:
                Bytes=decryption.if_no_8_bytes(Bytes) # we call this function if the block is not 8 bytes (happens at the end of the raw data)
            plain_text += decryption.decrypt(Bytes, key)
        return plain_text

    def decrypt(data_block,key):
        decryptedCipher=b''
        for index,value in enumerate(data_block):
            key_bytes = bytes(key, 'utf-8') 
            decBlock=key_bytes[index]^value # Xoring the key with file content
            inv_subB=S_box_inv[decBlock] # subtituting file content with its mapped value in SBox_inverse
            decryptedCipher+=bytes.fromhex('{0:02x}'.format(inv_subB))
        return decryptedCipher

def reading_file():
        cipher_file=open(argv[1],"rb")
        return cipher_file.read() # return the raw data of the file


welcome.banner()

file = reading_file()[-8:]

type= input("What's Your file type (jpg,pdf,png,docx,txt): ")
start=datetime.now()
for i in range(0,256):
    for j in range(0,256):
        for k in range(0,256):
            for m in range(0,256):
                testedKey = f"{hex(i)[2:].zfill(2)}{hex(j)[2:].zfill(2)}{hex(k)[2:].zfill(2)}{hex(m)[2:].zfill(2)}"
                
                print(testedKey)

                if type == "jpg":
                    decrypted_file=decryption.deviding_block(file,testedKey)
                    if decrypted_file[0:8]== b"\xff\xd8\xff\xe0\x00\x10\x4a\x46":       
                        print("found key :",testedKey)
                        print(f"ended in {datetime.now()-start} seconds")
                        exit()



                elif type == "png":
                    decrypted_file=decryption.deviding_block(file,testedKey)
                    if decrypted_file[0:8]==b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a":
                        print("found key :",testedKey)
                        print(f"ended in {datetime.now()-start} seconds")
                        exit()



                elif type == "pdf" :
                    decrypted_file=decryption.deviding_block(file,testedKey)
                    if decrypted_file[0:8]==b"\x25\x50\x44\x46\x2d\x31\x2e\x37":
                        print("found key :",testedKey)
                        print(f"ended in {datetime.now()-start} seconds")
                        exit()
                    elif decrypted_file[0:8]==b"\x25\x50\x44\x46\x2d\x31\x2e\x36":
                        print("found key :",testedKey)
                        print(f"ended in {datetime.now()-start} seconds")
                        exit()


        
                elif type == "docx":
                    decrypted_file=decryption.deviding_block(file,testedKey)
                    if decrypted_file[0:8] == b"\x50\x4b\x03\x04\x14\x00\x06\x00\x37":
                        print("found key :",testedKey)
                        print(f"ended in {datetime.now()-start} seconds")
                        exit()



                elif type == "txt":
                    file = reading_file()
                    decrypted_file=decryption.deviding_block(file,testedKey)
                    print(decrypted_file)
                    if testedKey == "000fffff":
                        print("tested from 00000000 to 000fffff")
                        exit()
                           
                else:
                    print("Please type a valid file type")
                    exit()