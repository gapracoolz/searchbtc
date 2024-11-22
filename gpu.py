import pycuda.autoinit
import pycuda.driver as cuda
from pycuda.compiler import SourceModule
import numpy as np
import time
import os
from Crypto.Hash import SHA256, RIPEMD160
import base58
import ecdsa
from bech32 import bech32_encode, convertbits
import threading
from colorthon import Colors
import hashlib
import coincurve

# COLORS CODE
RED = Colors.RED
GREEN = Colors.GREEN
YELLOW = Colors.YELLOW
CYAN = Colors.CYAN
WHITE = Colors.WHITE
RESET = Colors.RESET

# CUDA Kernel for key generation
cuda_code = """
__global__ void generate_keys(unsigned char *private_keys, unsigned char *public_keys, int n) {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    if (idx < n) {
        // Generate random private key
        for (int i = 0; i < 32; i++) {
            private_keys[idx * 32 + i] = (unsigned char)(clock64() % 256);
        }
    }
}
"""

def getClear():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def Rich_Loader(file):
    try:
        with open(file, 'r') as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        print(f"{RED}Error: File {file} not found{RESET}")
        return []
    except Exception as e:
        print(f"{RED}Error loading file: {str(e)}{RESET}")
        return []

def getHeader(richFile, loads, found):
    getClear()
    output = f"""
{RED}➜{RESET} {WHITE}BTC {RESET}{CYAN}Private Key Checker {RESET} v1 {GREEN}BETA{RESET} {YELLOW}GPU Edition{RESET}
{RED}➜{RESET} {WHITE}AUTHOR {RESET}{CYAN}:{RESET}-{GREEN}GapraCooLz{RESET}
{RED}▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬{RESET}
{RED}[{RESET}{WHITE}►{RESET}{RED}]{RESET}{GREEN} Address File     :{RESET}{CYAN} {richFile}                {RESET}
{RED}[{RESET}{WHITE}►{RESET}{RED}]{RESET}{GREEN} Result Checked   :{RESET}{CYAN} {loads}                   {RESET}
{RED}[{RESET}{WHITE}►{RESET}{RED}]{RESET}{GREEN} Matched Address  :{RESET}{CYAN} {found}                   {RESET}
"""
    print(output)

def bech32m_encode(witver, witprog):
    """Encode a segwit address with bech32m"""
    ret = bech32_encode('bc', [witver] + convertbits(witprog, 8, 5))
    if ret is None:
        return None
    return ret

class GPUAddressGenerator:
    def __init__(self, batch_size=1024):
        self.batch_size = batch_size
        self.mod = SourceModule(cuda_code)
        self.generate_keys = self.mod.get_function("generate_keys")
        
        # Allocate GPU memory
        self.private_keys_gpu = cuda.mem_alloc(32 * batch_size)
        self.public_keys_gpu = cuda.mem_alloc(64 * batch_size)
        
        # Optimize kernel parameters
        device = cuda.Device(0)
        max_threads = device.max_threads_per_block
        self.block_size = min(256, max_threads)
        self.grid_size = (self.batch_size + self.block_size - 1) // self.block_size

    def generate_bitcoin_address(self, private_key):
        try:
            # Generate WIF
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

            # Generate addresses
            # P2PKH
            hash160 = RIPEMD160.new()
            hash160.update(SHA256.new(bytes.fromhex(public_key)).digest())
            public_key_hash = '00' + hash160.hexdigest()
            checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
            p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

            # Compressed P2PKH
            hash160 = RIPEMD160.new()
            hash160.update(SHA256.new(bytes.fromhex(compressed_public_key)).digest())
            public_key_hash = '00' + hash160.hexdigest()
            checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
            compressed_p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

            # P2SH
            redeem_script = '21' + compressed_public_key + 'ac'
            hash160 = RIPEMD160.new()
            hash160.update(SHA256.new(bytes.fromhex(redeem_script)).digest())
            script_hash = '05' + hash160.hexdigest()
            checksum = SHA256.new(SHA256.new(bytes.fromhex(script_hash)).digest()).hexdigest()[:8]
            p2sh_address = base58.b58encode(bytes.fromhex(script_hash + checksum))

            # Bech32
            witness_program = bytes([0x00, 0x14]) + hash160.digest()
            bech32_address = bech32_encode('bc', convertbits(witness_program, 8, 5))

            # Taproot
            internal_key = coincurve.PublicKey.from_secret(private_key).format(compressed=True)
            taproot_pubkey = internal_key[1:]
            tweak = hashlib.sha256(b'TapTweak' + taproot_pubkey).digest()
            taproot_address = bech32m_encode(1, taproot_pubkey)

            return {
                'private_key': private_key.hex(),
                'WIF': WIF.decode(),
                'p2pkh_address': p2pkh_address.decode(),
                'compressed_p2pkh_address': compressed_p2pkh_address.decode(),
                'p2sh_address': p2sh_address.decode(),
                'bech32_address': bech32_address,
                'taproot_address': taproot_address
            }
        except Exception as e:
            print(f"{RED}Error generating address: {str(e)}{RESET}")
            return None

    def generate_batch(self):
        try:
            # Generate private keys on GPU
            private_keys = np.zeros((self.batch_size, 32), dtype=np.uint8)
            
            self.generate_keys(
                self.private_keys_gpu,
                self.public_keys_gpu,
                np.int32(self.batch_size),
                block=(self.block_size, 1, 1),
                grid=(self.grid_size, 1)
            )
            
            # Copy results back to CPU
            cuda.memcpy_dtoh(private_keys, self.private_keys_gpu)
            
            # Generate addresses for each private key
            addresses = []
            for private_key in private_keys:
                addr_info = self.generate_bitcoin_address(private_key.tobytes())
                if addr_info:
                    addresses.append(addr_info)
                    
            return addresses
            
        except cuda.RuntimeError as e:
            print(f"{RED}GPU Error: {str(e)}{RESET}")
            return []

def write_found(address_type, address, private_key):
    try:
        with open('Found.txt', 'a') as f:
            f.write(f"{address_type}: {address}\n"
                   f"Private Key: {private_key}\n"
                   f"{'-' * 66}\n")
    except Exception as e:
        print(f"{RED}Error writing to Found.txt: {str(e)}{RESET}")

def MainCheckGPU():
    target_file = 'btc.txt'
    try:
        Targets = Rich_Loader(target_file)
        if not Targets:
            print(f"{RED}No targets loaded. Exiting...{RESET}")
            return

        z = 0
        wf = 0
        lg = 0
        generator = GPUAddressGenerator(batch_size=1024)  # Adjust batch size as needed
        
        getHeader(richFile=target_file, loads=lg, found=wf)
        
        while True:
            try:
                # Generate batch of addresses
                addresses = generator.generate_batch()
                z += len(addresses)
                
                # Check all addresses in batch
                for addr_info in addresses:
                    for address_type, address in [
                        ('P2PKH Address', addr_info['p2pkh_address']),
                        ('Compressed P2PKH Address', addr_info['compressed_p2pkh_address']),
                        ('P2SH Address', addr_info['p2sh_address']),
                        ('Bech32 Address', addr_info['bech32_address']),
                        ('Taproot Address', addr_info['taproot_address'])
                    ]:
                        if address in Targets:
                            wf += 1
                            open('Found.txt', 'a').write(address_type, address, addr_info['WIF'])
                
                if z % 100000 == 0:
                    lg += 100000
                    getHeader(richFile=target_file, loads=lg, found=wf)
                    print(f"Generated: {lg} (GPU Batch) ...")
                else:
                    lct = time.localtime()
                    tm = time.strftime("%Y-%m-%d %H:%M:%S", lct)
                    print(f"[{tm}][Total: {z} Check: {z * 5}] #Found: {wf} ", end="\r")
                    
            except Exception as e:
                print(f"{RED}Error in main loop: {str(e)}{RESET}")
                
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Program stopped by user{RESET}")

if __name__ == '__main__':
    try:
        print(f"{YELLOW}Initializing GPU...{RESET}")
        t = threading.Thread(target=MainCheckGPU)
        t.start()
        t.join()
    except Exception as e:
        print(f"{RED}Error starting program: {str(e)}{RESET}")
