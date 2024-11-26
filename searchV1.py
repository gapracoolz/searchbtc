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
import sqlite3
from typing import Optional, List

# COLORS CODE
RED = Colors.RED
GREEN = Colors.GREEN
YELLOW = Colors.YELLOW
CYAN = Colors.CYAN
WHITE = Colors.WHITE
RESET = Colors.RESET

class AddressGenerator:
    def __init__(self):
        self.counter = 0
        self.found = 0
        self.lock = threading.Lock()
    
    @staticmethod
    def validate_address(address: str, addr_type: str) -> bool:
        """Validate Bitcoin address format"""
        try:
            if address is None:
                return False
                
            if addr_type == 'p2pkh':
                return address.startswith('1') and len(address) >= 26 and len(address) <= 35
            elif addr_type == 'p2sh':
                return address.startswith('3') and len(address) >= 26 and len(address) <= 35
            elif addr_type == 'bech32':
                return address.startswith('bc1q') and len(address) == 42
            elif addr_type == 'taproot':
                if not address.startswith('bc1p'):
                    return False
                hrp, data = bech32_decode(address)
                if hrp != 'bc' or data is None:
                    return False
                converted = convertbits(data[1:], 5, 8, False)
                return converted is not None and len(converted) == 32 and data[0] == 1
            return False
        except Exception:
            return False

    @staticmethod
    def get_bech32_address(public_key_hash: bytes) -> Optional[str]:
        """Generate proper Bech32 address"""
        try:
            witness_version = 0
            converted_bits = convertbits(public_key_hash, 8, 5, True)
            if converted_bits is None:
                return None
            address = bech32_encode('bc', [witness_version] + converted_bits)
            return address if address is not None else None
        except Exception:
            return None

    def generate_taproot_address(self, private_key: bytes) -> Optional[str]:
        """Generate Taproot address from private key"""
        try:
            # Create key pair using coincurve
            privkey = coincurve.PrivateKey(private_key)
            pubkey = privkey.public_key
            
            # Get x-only pubkey (remove the first byte and keep only x coordinate)
            x_only_pubkey = pubkey.format(compressed=True)[1:]
            
            # Tweak the public key
            tweak_bytes = hashlib.sha256(b'TapTweak' + x_only_pubkey).digest()
            tweaked_privkey = coincurve.PrivateKey(tweak_bytes)
            tweaked_pubkey = tweaked_privkey.public_key
            
            # Get the final tweaked point
            output_key = tweaked_pubkey.format(compressed=True)[1:]
            
            # Convert to 5-bit array for bech32m encoding
            converted_bits = convertbits(output_key, 8, 5, True)
            if converted_bits is None:
                return None
                
            # Create Taproot address with witness v1
            address = bech32_encode('bc', [1] + converted_bits)
            return address
            
        except Exception as e:
            print(f"{RED}Taproot generation error: {str(e)}{RESET}")
            return None
    def generate_bitcoin_address(self) -> dict:
        """Generate Bitcoin address with all formats"""
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

        # Generate P2PKH address
        hash160 = RIPEMD160.new()
        hash160.update(SHA256.new(bytes.fromhex(public_key)).digest())
        public_key_hash = '00' + hash160.hexdigest()
        checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
        p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

        # Generate compressed P2PKH address
        hash160 = RIPEMD160.new()
        hash160.update(SHA256.new(bytes.fromhex(compressed_public_key)).digest())
        public_key_hash = '00' + hash160.hexdigest()
        checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
        compressed_p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

        # Generate P2SH address
        redeem_script = '21' + compressed_public_key + 'ac'
        hash160 = RIPEMD160.new()
        hash160.update(SHA256.new(bytes.fromhex(redeem_script)).digest())
        script_hash = '05' + hash160.hexdigest()
        checksum = SHA256.new(SHA256.new(bytes.fromhex(script_hash)).digest()).hexdigest()[:8]
        p2sh_address = base58.b58encode(bytes.fromhex(script_hash + checksum))

        # Generate Bech32 address
        hash160 = RIPEMD160.new()
        hash160.update(SHA256.new(bytes.fromhex(compressed_public_key)).digest())
        pubkey_hash = hash160.digest()
        bech32_address = self.get_bech32_address(pubkey_hash)

        # Generate Taproot Address
        taproot_address = self.generate_taproot_address(private_key)

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
def getClear():
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')
def Rich_Loader(file):
    with open(file, 'r') as f:
        return [line.strip() for line in f]

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

def write_found(address_type, address, private_key):
    try:
        with open('Found.txt', 'a') as f:
            f.write(f"{address_type}: {address}\n"
                   f"Private Key: {private_key}\n"
                   f"{'-' * 66}\n")
    except Exception as e:
        print(f"{RED}Error writing to Found.txt: {str(e)}{RESET}")

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
        
        bitcoin_address = AddressGenerator()
        
        while True:
            z += 1
            try:
                address_info = bitcoin_address.generate_bitcoin_address()
                
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
    t = threading.Thread(target=MainCheck)
    t.start()
    t.join()