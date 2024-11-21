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

class MaliGPUAddressGenerator:
    def __init__(self, batch_size=512):  # Smaller batch size for mobile GPU
        self.batch_size = batch_size
        
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
            
            print(f"{GREEN}Successfully initialized Mali GPU{RESET}")
            print(f"Device: {self.device.name}")
            print(f"Max work group size: {self.device.max_work_group_size}")
            
        except Exception as e:
            print(f"{RED}Error initializing Mali GPU: {str(e)}{RESET}")
            raise

    def generate_bitcoin_address(self, private_key):
        try:
            # [Previous bitcoin address generation code remains the same]
            # ... [Keep the same code from the previous version]
            
        except Exception as e:
            print(f"{RED}Error generating address: {str(e)}{RESET}")
            return None

    def generate_batch(self):
        try:
            # Prepare buffers
            private_keys = np.zeros((self.batch_size, 32), dtype=np.uint8)
            private_keys_buf = cl.Buffer(
                self.ctx,
                cl.mem_flags.WRITE_ONLY,
                size=private_keys.nbytes
            )
            
            # Set kernel arguments
            seed = np.uint32(int(time.time() * 1000000))
            
            # Execute kernel with appropriate work group size
            local_size = min(self.device.max_work_group_size, 64)  # Mali-optimized
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
            # Clean up OpenCL buffers
            if 'private_keys_buf' in locals():
                private_keys_buf.release()
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

# Modified getHeader function to include temperature and battery
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

# Modified MainCheckMaliGPU function with temperature and battery monitoring
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
        
        # Initialize Mali GPU generator with smaller batch size
        generator = MaliGPUAddressGenerator(batch_size=512)
        
        # Initial temperature and battery check
        temp = check_temperature()
        battery = check_battery()
        getHeader(richFile=target_file, loads=lg, found=wf, temp=temp, battery=battery)
        
        while True:
            try:
                # Check temperature and battery every iteration
                temp = check_temperature()
                battery = check_battery()
                
                # Temperature protection
                if temp > 70:
                    print(f"\n{RED}WARNING: GPU Temperature too high ({temp}°C)! Cooling down...{RESET}")
                    time.sleep(10)  # Cool down period
                    continue
                
                # Battery protection
                if battery < 20:
                    print(f"\n{YELLOW}WARNING: Low battery ({battery}%)! Connect charger!{RESET}")
                    if battery < 10:
                        print(f"{RED}Critical battery level. Stopping...{RESET}")
                        break
                
                # Generate batch of addresses
                addresses = generator.generate_batch()
                z += len(addresses)
                
                # Check addresses
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
                
                if z % 10000 == 0:  # Update display every 10000 iterations
                    lg += 10000
                    getHeader(richFile=target_file, loads=lg, found=wf, temp=temp, battery=battery)
                    print(f"Generated: {lg} (Mali GPU Batch) ...")
                else:
                    lct = time.localtime()
                    tm = time.strftime("%Y-%m-%d %H:%M:%S", lct)
                    print(f"[{tm}][Total: {z} Check: {z * 5}] #Found: {wf} "
                          f"Temp: {temp}°C Bat: {battery}% ", end="\r")
                    
                # Dynamic sleep based on temperature
                if temp > 60:
                    time.sleep(0.005)  # Longer delay when hot
                else:
                    time.sleep(0.001)  # Normal delay
                    
            except Exception as e:
                print(f"{RED}Error in main loop: {str(e)}{RESET}")
                time.sleep(1)  # Wait before retrying
                
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Program stopped by user{RESET}")
        # Final temperature and battery status
        print(f"Final Temperature: {check_temperature()}°C")
        print(f"Final Battery Level: {check_battery()}%")

# Modified MaliGPUAddressGenerator class to include temperature monitoring
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

    def generate_batch(self):
        # Check temperature before batch generation
        temp = check_temperature()
        if temp > 70 and not self.temp_warning_shown:
            print(f"{RED}WARNING: High temperature detected ({temp}°C){RESET}")
            self.temp_warning_shown = True
        elif temp <= 65:
            self.temp_warning_shown = False
            
if __name__ == '__main__':
    try:
        print(f"{YELLOW}Initializing Mali GPU...{RESET}")
        t = threading.Thread(target=MainCheckMaliGPU)
        t.start()
        t.join()
    except Exception as e:
        print(f"{RED}Error starting program: {str(e)}{RESET}")
