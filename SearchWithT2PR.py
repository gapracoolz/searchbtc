import time
import os
from Crypto.Hash import SHA256, RIPEMD160
import base58
import ecdsa
from bech32 import bech32_encode, convertbits, bech32_decode
import threading
from colorthon import Colors
import hashlib
import coincurve

# COLORS CODE --------------------
RED = Colors.RED
GREEN = Colors.GREEN
YELLOW = Colors.YELLOW
CYAN = Colors.CYAN
WHITE = Colors.WHITE
RESET = Colors.RESET
# COLORS CODE -------------------

def getClear():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def Rich_Loader(file):
    with open(file, 'r') as f:
        return [line.strip() for line in f]

def getHeader(richFile, loads, found):
    print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}][Loaded: {loads}] #Found: {found} [Target: {richFile}]\n")
    
def bech32m_encode(witver, witprog):
    """Encode a segwit address with bech32m"""
    ret = bech32_encode('bc', [witver] + convertbits(witprog, 8, 5))
    if ret is None:
        return None
    return ret

def generate_bitcoin_address():
    # Generate private key
    private_key = os.urandom(32)
    fullkey = '80' + private_key.hex()
    sha256a = SHA256.new(bytes.fromhex(fullkey)).hexdigest()
    sha256b = SHA256.new(bytes.fromhex(sha256a)).hexdigest()
    WIF = base58.b58encode(bytes.fromhex(fullkey + sha256b[:8]))

    # Get public key
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    public_key = '04' + x.to_bytes(32, 'big').hex() + y.to_bytes(32, 'big').hex()

    # Get compressed public key
    compressed_public_key = '02' if y % 2 == 0 else '03'
    compressed_public_key += x.to_bytes(32, 'big').hex()

    # Get P2PKH address
    hash160 = RIPEMD160.new()
    hash160.update(SHA256.new(bytes.fromhex(public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

    # Get compressed P2PKH address
    hash160 = RIPEMD160.new()
    hash160.update(SHA256.new(bytes.fromhex(compressed_public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    compressed_p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

    # Get P2SH address
    redeem_script = '21' + compressed_public_key + 'ac'
    hash160 = RIPEMD160.new()
    hash160.update(SHA256.new(bytes.fromhex(redeem_script)).digest())
    script_hash = '05' + hash160.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(script_hash)).digest()).hexdigest()[:8]
    p2sh_address = base58.b58encode(bytes.fromhex(script_hash + checksum))

    # Get Bech32 address
    witness_program = bytes([0x00, 0x14]) + hash160.digest()
    bech32_address = bech32_encode('bc', convertbits(witness_program, 8, 5))

    # Generate Taproot Address
    internal_key = coincurve.PublicKey.from_secret(private_key).format(compressed=True)
    
    # Tagged hash for taproot
    def tagged_hash(tag: str, msg: bytes) -> bytes:
        tag_hash = hashlib.sha256(tag.encode()).digest()
        return hashlib.sha256(tag_hash + tag_hash + msg).digest()
    
    # Create taproot output key
    taproot_pubkey = internal_key[1:]  # Remove the prefix byte
    tweak = tagged_hash('TapTweak', taproot_pubkey)
    
    # Generate taproot address
    taproot_address = bech32m_encode(1, taproot_pubkey)

    return {
        'private_key': private_key.hex(),
        'WIF': WIF.decode(),
        'public_key': public_key,
        'compressed_public_key': compressed_public_key,
        'p2pkh_address': p2pkh_address.decode(),
        'compressed_p2pkh_address': compressed_p2pkh_address.decode(),
        'p2sh_address': p2sh_address.decode(),
        'bech32_address': bech32_address,
        'taproot_address': taproot_address
    }
    
def getHeader(richFile, loads, found):
    getClear()
    output = f"""
{RED}➜{RESET} {WHITE}BTC {RESET}{CYAN}Private Key Checker {RESET} v1 {GREEN}BETA{RESET}
{RED}➜{RESET} {WHITE}AUTHOR {RESET}{CYAN}:{RESET}-{GREEN}GapraCooLz{RESET}
{RED}▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬{RESET}
{RED}[{RESET}{WHITE}►{RESET}{RED}]{RESET}{GREEN} Address File     :{RESET}{CYAN} {richFile}                {RESET}
{RED}[{RESET}{WHITE}►{RESET}{RED}]{RESET}{GREEN} Result Checked   :{RESET}{CYAN} {loads}                   {RESET}
{RED}[{RESET}{WHITE}►{RESET}{RED}]{RESET}{GREEN} Matched Address  :{RESET}{CYAN} {found}                   {RESET}
"""
    print(output)
    
def MainCheck():
    target_file = 'btc.txt'
    try:
        Targets = Rich_Loader(target_file)
        if not Targets:
            print(f"{RED}No targets loaded. Exiting...{RESET}")
            return

        z = 0
        wf = 0
        lg = 0
        getHeader(richFile=target_file, loads=lg, found=wf)
        
        while True:
            z += 1
            try:
                address_info = generate_bitcoin_address()
                
                # Check addresses including Taproot
                for address_type, address in [
                    ('P2PKH Address', address_info['p2pkh_address']),
                    ('Compressed P2PKH Address', address_info['compressed_p2pkh_address']),
                    ('P2SH Address', address_info['p2sh_address']),
                    ('Bech32 Address', address_info['bech32_address']),
                    ('Taproot Address', address_info['taproot_address'])
                ]:
                    if address in Targets:
                        wf += 1
                        write_found(address_type, address, address_info['WIF'])
                
                if z % 100000 == 0:
                    lg += 100000
                    getHeader(richFile=target_file, loads=lg, found=wf)
                    print(f"Generated: {lg} (SHA-256 - HEX) ...")
                else:
                    lct = time.localtime()
                    tm = time.strftime("%Y-%m-%d %H:%M:%S", lct)
                    print(f"[{tm}][Total: {z} Check: {z * 5}] #Found: {wf} ", end="\r")
                    
            except Exception as e:
                print(f"{RED}Error in main loop: {str(e)}{RESET}")
                
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Program stopped by user{RESET}")
        
if __name__ == '__main__':
    thread_count = 4  # Adjust based on CPU cores
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=MainCheck)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
