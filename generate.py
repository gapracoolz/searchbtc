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
    def getClear():
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')

    @staticmethod
    def create_database():
        try:
            conn = sqlite3.connect('bitcoin_wallet.db', check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS wallets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    private_key TEXT NOT NULL,
                    wif TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    compressed_public_key TEXT NOT NULL,
                    p2pkh_address TEXT NOT NULL,
                    compressed_p2pkh_address TEXT NOT NULL,
                    p2sh_address TEXT NOT NULL,
                    bech32_address TEXT NOT NULL,
                    taproot_address TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            return conn
        except sqlite3.Error as e:
            print(f"{RED}Database Error: {str(e)}{RESET}")
            return None

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

    def save_wallet(self, wallet_data: dict) -> bool:
        """Save wallet data to database"""
        try:
            conn = self.create_database()
            if conn is None:
                return False
            
            # Validate addresses before saving
            if not all([
                self.validate_address(wallet_data['p2pkh_address'], 'p2pkh'),
                self.validate_address(wallet_data['p2sh_address'], 'p2sh'),
                self.validate_address(wallet_data['bech32_address'], 'bech32'),
                wallet_data['taproot_address'] is None or self.validate_address(wallet_data['taproot_address'], 'taproot')
            ]):
                print(f"{RED}Invalid address format detected{RESET}")
                return False

            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO wallets (
                    private_key,
                    wif,
                    public_key,
                    compressed_public_key,
                    p2pkh_address,
                    compressed_p2pkh_address,
                    p2sh_address,
                    bech32_address,
                    taproot_address
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                wallet_data['private_key'],
                wallet_data['WIF'],
                wallet_data['public_key'],
                wallet_data['compressed_public_key'],
                wallet_data['p2pkh_address'],
                wallet_data['compressed_p2pkh_address'],
                wallet_data['p2sh_address'],
                wallet_data['bech32_address'],
                wallet_data['taproot_address']
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except sqlite3.Error as e:
            print(f"{RED}Database Error: {str(e)}{RESET}")
            return False
    def save_to_file(self, wallet_data: dict, filename: str = "found_wallets.txt") -> None:
        """Save wallet data to text file"""
        try:
            with open(filename, "a") as f:
                f.write(f"\n{'='*50}\n")
                f.write(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Private Key: {wallet_data['private_key']}\n")
                f.write(f"WIF: {wallet_data['WIF']}\n")
                f.write(f"Legacy Address (P2PKH): {wallet_data['p2pkh_address']}\n")
                f.write(f"Compressed P2PKH: {wallet_data['compressed_p2pkh_address']}\n")
                f.write(f"Segwit Address (P2SH): {wallet_data['p2sh_address']}\n")
                f.write(f"Native Segwit (Bech32): {wallet_data['bech32_address']}\n")
                f.write(f"Taproot Address: {wallet_data['taproot_address']}\n")
                f.write(f"{'='*50}\n")
        except IOError as e:
            print(f"{RED}File Error: {str(e)}{RESET}")

    def display_progress(self, start_time: float) -> None:
        """Display generation progress"""
        elapsed_time = time.time() - start_time
        speed = self.counter / elapsed_time if elapsed_time > 0 else 0
        print(f"{YELLOW}Generated: {self.counter:,} addresses | "
              f"Speed: {speed:.2f} addr/s | "
              f"Found: {self.found} | "
              f"Time: {elapsed_time:.2f}s{RESET}", end='\r')

    def run_generator(self, delay: float, save_to_file: bool) -> None:
        """Main generation loop"""
        start_time = time.time()
        last_display = 0

        try:
            while True:
                wallet_data = self.generate_bitcoin_address()
                
                with self.lock:
                    self.counter += 1
                
                # Save to database
                if self.save_wallet(wallet_data):
                    if save_to_file:
                        self.save_to_file(wallet_data)
                
                # Update display every 0.5 seconds
                current_time = time.time()
                if current_time - last_display >= 0.5:
                    self.display_progress(start_time)
                    last_display = current_time
                
                time.sleep(delay)

        except KeyboardInterrupt:
            print(f"\n{YELLOW}Generator stopped by user{RESET}")
        except Exception as e:
            print(f"\n{RED}Error: {str(e)}{RESET}")

def test_specific_key():
    """Test function for specific private key"""
    generator = AddressGenerator()
    
    # Test case
    private_key = bytes.fromhex("8ec8425b69c726b5f94e16e899bc734880e7aaed833424bf3febe374c648b1f2")
    expected_address = "bc1pckwzpvdrqmv4gt8mdq8l2jvm5er7tuc2gxe87e9juyfrrwhxgmksf2p8dq"
    
    taproot_address = generator.generate_taproot_address(private_key)
    
    print(f"{CYAN}=== Taproot Address Test ==={RESET}")
    print(f"Private Key: {private_key.hex()}")
    print(f"Generated Taproot Address: {taproot_address}")
    print(f"Expected Taproot Address: {expected_address}")
    print(f"Matches Expected: {GREEN if taproot_address == expected_address else RED}"
          f"{taproot_address == expected_address}{RESET}")
    print(f"Is Valid: {GREEN if generator.validate_address(taproot_address, 'taproot') else RED}"
          f"{generator.validate_address(taproot_address, 'taproot')}{RESET}")

def main():
    generator = AddressGenerator()
    generator.getClear()
    
    try:
        # Speed selection
        print(f"{YELLOW}Select generation speed:{RESET}")
        print(f"{WHITE}1. Fast (No delay)")
        print(f"2. Medium (0.5 second delay)")
        print(f"3. Slow (1 second delay){RESET}")
        
        speed_choice = input(f"\n{CYAN}Enter your choice (1-3): {RESET}")
        delay = {'1': 0, '2': 0.5, '3': 1}.get(speed_choice, 0.5)
        
        # File saving option
        print(f"\n{YELLOW}Save results to file?{RESET}")
        print(f"{WHITE}1. Yes")
        print(f"2. No{RESET}")
        
        save_to_file = input(f"\n{CYAN}Enter your choice (1-2): {RESET}") == '1'
        
        # Clear screen and start
        generator.getClear()
        print(f"{YELLOW}Starting Bitcoin wallet generator...{RESET}")
        print(f"{CYAN}Press Ctrl+C to stop the generator{RESET}\n")
        
        # Start generator
        generator.run_generator(delay, save_to_file)
        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Generator stopped by user{RESET}")
    finally:
        # Show final stats
        print(f"\n{CYAN}=== Final Statistics ==={RESET}")
        print(f"Total Generated: {generator.counter:,}")
        print(f"Total Found: {generator.found}")
        
        # Show file locations
        db_path = os.path.abspath('bitcoin_wallet.db')
        print(f"\n{CYAN}Database location: {db_path}{RESET}")
        if save_to_file:
            file_path = os.path.abspath('found_wallets.txt')
            print(f"{CYAN}Text file location: {file_path}{RESET}")

if __name__ == "__main__":
    # Choose whether to run the generator or test a specific key
    print(f"{YELLOW}Choose operation mode:{RESET}")
    print(f"{WHITE}1. Run wallet generator")
    print(f"2. Test specific private key{RESET}")
    
    mode = input(f"\n{CYAN}Enter your choice (1-2): {RESET}")
    
    if mode == "2":
        test_specific_key()
    else:
        main()
