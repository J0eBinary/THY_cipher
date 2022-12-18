
from sys import argv
if len(argv) != 4:
    print("Usage : encrypt_THY_project.py <KEY> <inputFile> <outputFile>")
    exit(-1)
S_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)
# welcoming class that has all greetings functions
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
        print('''     _________
    / ======= \\
   / __________\\
  | ___________ |
  | | -       | |
  | |         | |
  | |_________| |________________________
  \=____________/   ENCRYPTING......     )
  / """"""""""" \                       /
 / ::::::::::::: \                  =D-'
(_________________)\n''')


#class for reading file and writing to a file
class reading_writing:
    def reading_file():
        plain_file=open(argv[2],"rb")
        return plain_file.read() # return the raw data of the file
    
    def writing_encrypted_file(file_to_write,encData):
        cipherFile=open(file_to_write,"wb")
        cipherFile.write(encData) # write the encrypted data to the file 



class encryptingProcess:
    def __init__():
        print()
    def getkey():
        key= argv[1]
        if len(key)!=8: # if the key is not 8 chars, the program is terminated
            print("the key should be 8 characters (32 bit):")
            exit()                                                         
        return key

    def if_no_8_bytes(Bytes): # we call this function if the last block is not 8 bytes long
        n=8-len(Bytes)%8
        null_added=n*'\x00' 
        null_added=bytes(null_added,'utf-8')
        # adding a null byte so it doesn't affect the file, also making the last block = 8 bytes long
        return Bytes + null_added

    def deviding_block(raw,key):
        cipher_text=b''

        for i in range(0,len(raw),8): # deviding raw data as 8 bytes block
            Bytes=raw[i:i+8]
            
            if len(Bytes)%8!=0:
                
                Bytes=encryptingProcess.if_no_8_bytes(Bytes) # we call this function if the block is not 8 bytes (happens at the end of the raw data)
            cipher_text += encryptingProcess.encrypt(Bytes, key)
        return cipher_text

    def encrypt(data_block,key_to_encrypt):
        encrypted_data_b=b''
        for index,value in enumerate(data_block):
            substituted =S_box[value]# substituting data from the s box (same as AES)
            key_as_bytes=bytes(key_to_encrypt, 'utf-8')#converting the key (string) to bytes
            encB=key_as_bytes[index] ^ substituted # XOR with the key given by the user 
            encrypted_data_b = encrypted_data_b + bytes.fromhex('{0:02x}'.format(encB)) # converting to hexadecimal representation
        return encrypted_data_b        
        

welcome.welcoming_banner()#displaying the banner
raw_data=reading_writing.reading_file() # raw data (before encryption)
key=encryptingProcess.getkey()
welcome.banner()
enc=encryptingProcess.deviding_block(raw_data,key)[::-1] # encrypting the data, after that, reverse it (permutation)
reading_writing.writing_encrypted_file(argv[3],enc) # saving the encrypted data to the output file 
print(f"the first 20 bytes of the plain file are:{raw_data[0:20]}")
print(f"Your 32 bit key is:{key}\n")
print(f"The first 20 bytes of your encrypted file are:{enc[0:20]}",)
print(f"now your encrypted data is saved in this file '{argv[3]}'")
