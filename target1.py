import requests
from bs4 import BeautifulSoup
import random
import time
import logging
from concurrent.futures import ThreadPoolExecutor
import decimal
from tqdm import tqdm
import sys

class PrivateKeyPageScanner:
    def __init__(self):
        self.base_url = "https://privatekeys.pw/keys/bitcoin/"
        self.start_page = 1
        self.max_page = decimal.Decimal('2.573157538607E+1075')
        self.checked_pages = set()
        self.found_matches = {}
        self.target_addresses = set()
        self.session = requests.Session()
        self.progress_bar = None
        
        # Configure logging
        logging.basicConfig(
            filename='page_scan.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Configure session headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })

    def load_addresses(self, filename):
        """Load target addresses from file"""
        try:
            with open(filename, 'r') as file:
                self.target_addresses = set(line.strip() for line in file if line.strip())
            logging.info(f"Loaded {len(self.target_addresses)} addresses")
            print(f"Loaded {len(self.target_addresses)} addresses to check")
        except FileNotFoundError:
            logging.error(f"Address file {filename} not found")
            raise
        except Exception as e:
            logging.error(f"Error loading addresses: {e}")
            raise

    def scan_page(self, page_num):
        """Scan a single page for matches"""
        try:
            url = f"{self.base_url}{page_num}"
            
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                logging.warning(f"Failed to fetch page {page_num}: Status {response.status_code}")
                return False

            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract addresses from page
            addresses = []
            for addr_element in soup.select('.bitcoin-address'):  # Adjust selector
                addr = addr_element.text.strip()
                if addr in self.target_addresses:
                    private_key = self.extract_private_key(soup, addr_element)
                    self.found_matches[addr] = private_key
                    self.save_match(addr, private_key, page_num)
                    
                    # Print match without disrupting progress bar
                    tqdm.write(f"\nMatch found on page {page_num}!")
                    tqdm.write(f"Address: {addr}")
                    tqdm.write(f"Private Key: {private_key}\n")

            return True

        except Exception as e:
            logging.error(f"Error scanning page {page_num}: {e}")
            return False

    def extract_private_key(self, soup, addr_element):
        """Extract private key for matching address"""
        try:
            # Find private key element related to address
            private_key = "PRIVATE_KEY"  # Replace with actual extraction
            return private_key
        except Exception as e:
            logging.error(f"Error extracting private key: {e}")
            return "ERROR_EXTRACTING_KEY"

    def save_match(self, address, private_key, page_num):
        """Save found matches to file"""
        with open("found_matches.txt", "a") as f:
            f.write(f"Page: {page_num}\n")
            f.write(f"Address: {address}\n")
            f.write(f"Private Key: {private_key}\n")
            f.write("="*50 + "\n")

    def balanced_scan(self, random_probability=0.3, threads=4):
        """Balanced scanning approach with progress bar"""
        current_page = self.start_page
        batch_size = 100  # Number of pages per batch
        
        print(f"\nStarting balanced scan with {random_probability*100}% random probability")
        print("Press Ctrl+C to stop scanning\n")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            while current_page <= self.max_page:
                batch_pages = []
                
                # Create progress bar for current batch
                with tqdm(total=batch_size, 
                         desc="Current batch", 
                         unit="pages",
                         bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]') as pbar:
                    
                    while len(batch_pages) < batch_size:
                        if random.random() < random_probability:
                            page = random.randint(self.start_page, int(self.max_page))
                        else:
                            page = current_page
                            current_page += 1
                        
                        if page not in self.checked_pages:
                            batch_pages.append(page)
                            self.checked_pages.add(page)
                            
                            future = executor.submit(self.scan_page, page)
                            future.result()
                            
                            pbar.update(1)
                            pbar.set_postfix({
                                'Total Checked': len(self.checked_pages),
                                'Matches': len(self.found_matches)
                            })
                            
                            time.sleep(0.1)
                
                print(f"\nBatch complete. Total pages checked: {len(self.checked_pages)}")
                print(f"Total matches found: {len(self.found_matches)}")
                print("-" * 50)

def main():
    scanner = PrivateKeyPageScanner()
    
    # Load target addresses
    try:
        scanner.load_addresses("btc.txt")  # Changed to match your file name
    except FileNotFoundError:
        print("Please create btc.txt with addresses to search for")
        return
    except Exception as e:
        print(f"Error loading addresses: {e}")
        return

    # Get user preferences
    try:
        random_prob = float(input("Enter random probability (0.0-1.0) [default 0.3]: ") or 0.3)
        threads = int(input("Enter number of threads (1-8) [default 4]: ") or 4)
        
        random_prob = max(0.0, min(1.0, random_prob))
        threads = max(1, min(8, threads))
        
    except ValueError:
        print("Invalid input. Using default values.")
        random_prob = 0.3
        threads = 4

    try:
        scanner.balanced_scan(random_probability=random_prob, threads=threads)
    except KeyboardInterrupt:
        print("\n\nScanning stopped by user")
        print(f"Total pages checked: {len(scanner.checked_pages)}")
        print(f"Total matches found: {len(scanner.found_matches)}")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"Error occurred: {e}")
    finally:
        if scanner.found_matches:
            print("\nMatches have been saved to found_matches.txt")

if __name__ == "__main__":
    main()
