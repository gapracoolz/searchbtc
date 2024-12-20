import pyopencl as cl
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

# OpenCL kernel for Mali GPU
opencl_code = """
__kernel void generate_keys(__global uchar *private_keys,
                          const uint seed,
                          const int n) {
    int idx = get_global_id(0);
    if (idx < n) {
        // Simple random number generation
        uint state = seed + idx;
        for (int i = 0; i < 32; i++) {
            state = state * 1664525 + 1013904223;
            private_keys[idx * 32 + i] = (uchar)(state % 256);
        }
    }
}
"""

def check_temperature():
    try:
        with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
            temp = int(f.read().strip()) / 1000
            return temp
    except:
        return 0

def check_battery():
    try:
        with open('/sys/class/power_supply/battery/capacity', 'r') as f:
            return int(f.read().strip())
    except:
        return 100

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

def getHeader(richFile, loads, found, temp=0, battery=100):
    getClear()
    output = f"""
{RED}➜{RESET} {WHITE}BTC {RESET}{CYAN}Private Key Checker {RESET} v1 {GREEN}BETA{RESET} {YELLOW}Mali GPU Edition{RESET}
{RED}➜{RESET} {WHITE}AUTHOR {RESET}{CYAN}:{RESET}-{GREEN}GapraCooLz{RESET}
{RED}▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬{RESET}
{RED}[{RESET}{WHITE}►{RESET}{RED}]{RESET}{GREEN} Address File     :{RESET}{CYAN} {richFile}                {RESET}
{RED}[{RESET}{WHITE}►{RESET}{RED}]{RESET}{GREEN} Result Checked   :{RESET}{CYAN} {loads}                   {RESET}
{RED}[{RESET}{WHITE}►{RESET}{RED}]{RESET}{GREEN} Matched Address  :{RESET}{CYAN} {found}                   {RESET}
{RED}[{RESET}{WHITE}►{RESET}{RED}]{RESET}{GREEN} GPU Temperature  :{RESET}{YELLOW} {temp}°C                {RESET}
{RED}[{RESET}{WHITE}►{RESET}{RED}]{RESET}{GREEN} Battery Level    :{RESET}{YELLOW} {battery}%              {RESET}
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

class MaliGPUAddressGenerator:
    def __init__(self, batch_size=512):
        self.batch_size = batch_size
        self.temp_warning_shown = False
        
        try:
            # Initialize OpenCL
            platforms = cl.get_platforms()
            mali_platform = None
            
            # Find Mali GPU platform
            for platform in platforms:
                if "ARM" in platform.name or "Mali" in platform.name:
                    mali_platform = platform
                    break
            
            if mali_platform is None:
                raise Exception("Mali GPU platform not found")
            
            # Get Mali GPU device
            self.device = mali_platform.get_devices()[0]
            self.ctx = cl.Context([self.device])
            self.queue = cl.CommandQueue(self.ctx)
            
            # Build program
            self.program = cl.Program(self.ctx, opencl_code).build()
            
            # Initial temperature check
            initial_temp = check_temperature()
            initial_battery = check_battery()
            
            print(f"{GREEN}Successfully initialized Mali GPU{RESET}")
            print(f"Device: {self.device.name}")
            print(f"Initial Temperature: {initial_temp}°C")
            print(f"Initial Battery Level: {initial_battery}%")
            print(f"Max work group size: {self.device.max_work_group_size}")
            
        except Exception as e:
            print(f"{RED}Error initializing Mali GPU: {str(e)}{RESET}")
            raise

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
            taproot_address = bech32_encode('bc', [1] + convertbits(taproot_pubkey, 8, 5))

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
            # Check temperature before batch generation
            temp = check_temperature()
            if temp > 70 and not self.temp_warning_shown:
                print(f"{RED}WARNING: High temperature detected ({temp}°C){RESET}")
                self.temp_warning_shown = True
            elif temp <= 65:
                self.temp_warning_shown = False

            # Prepare buffers
            private_keys = np.zeros((self.batch_size, 32), dtype=np.uint8)
            private_keys_buf = cl.Buffer(
                self.ctx,
                cl.mem_flags.WRITE_ONLY,
                size=private_keys.nbytes
            )
            
            # Set kernel arguments
            seed = np.uint32(int(time.time() * 1000000))
            
            # Execute kernel
            local_size = min(self.device.max_work_group_size, 64)
            global_size = ((self.batch_size + local_size - 1) // local_size) * local_size
            
            self.program.generate_keys(
                self.queue,
                (global_size,),
                (local_size,),
                private_keys_buf,
                seed,
                np.int32(self.batch_size)
            )
            
            # Read results
            cl.enqueue_copy(self.queue, private_keys, private_keys_buf)
            self.queue.finish()
            
            # Generate addresses
            addresses = []
            for private_key in private_keys:
                addr_info = self.generate_bitcoin_address(private_key.tobytes())
                if addr_info:
                    addresses.append(addr_info)
            
            return addresses
            
        except cl.RuntimeError as e:
            print(f"{RED}GPU Error: {str(e)}{RESET}")
            return []
        finally:
            if 'private_keys_buf' in locals():
                private_keys_buf.release()

def MainCheckMaliGPU():
    target_file = 'btc.txt'
    try:
        Targets = Rich_Loader(target_file)
        if not Targets:
            print(f"{RED}No targets loaded. Exiting...{RESET}")
            return

        z = 0
        wf = 0
        lg = 0
        
        generator = MaliGPUAddressGenerator(batch_size=512)
        
        temp = check_temperature()
        battery = check_battery()
        getHeader(richFile=target_file, loads=lg, found=wf, temp=temp, battery=battery)
        
        while True:
            try:
                temp = check_temperature()
                battery = check_battery()
                
                if temp > 70:
                    print(f"\n{RED}WARNING: GPU Temperature too high ({temp}°C)! Cooling down...{RESET}")
                    time.sleep(10)
                    continue
                
                if battery < 20:
                    print(f"\n{YELLOW}WARNING: Low battery ({battery}%)! Connect charger!{RESET}")
                    if battery < 10:
                        print(f"{RED}Critical battery level. Stopping...{RESET}")
                        break
                
                addresses = generator.generate_batch()
                z += len(addresses)
                
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
                            write_found(address_type, address, addr_info['WIF'])
                
                if z % 10000 == 0:
                    lg += 10000
                    getHeader(richFile=target_file, loads=lg, found=wf, temp=temp, battery=battery)
                    print(f"Generated: {lg} (Mali GPU Batch) ...")
                else:
                    lct = time.localtime()
                    tm = time.strftime("%Y-%m-%d %H:%M:%S", lct)
                    print(f"[{tm}][Total: {z} Check: {z * 5}] #Found: {wf} "
                          f"Temp: {temp}°C Bat: {battery}% ", end="\r")
                    
                if temp > 60:
                    time.sleep(0.005)
                else:
                    time.sleep(0.001)
                    
            except Exception as e:
                print(f"{RED}Error in main loop: {str(e)}{RESET}")
                time.sleep(1)
                
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Program stopped by user{RESET}")
        print(f"Final Temperature: {check_temperature()}°C")
        print(f"Final Battery Level: {check_battery()}%")

if __name__ == '__main__':
    try:
        print(f"{YELLOW}Initializing Mali GPU...{RESET}")
        t = threading.Thread(target=MainCheckMaliGPU)
        t.start()
        t.join()
    except Exception as e:
        print(f"{RED}Error starting program: {str(e)}{RESET}")
