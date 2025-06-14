import time
import hashlib
import hmac
import itertools
import numpy as np
import pyopencl as cl
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from concurrent.futures import ThreadPoolExecutor

# ---------------------- CONFIGURATION ----------------------

CANDIDATE_WORDS = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve",
    # Tambahkan 230 kata Anda di sini
]

DESTINY_WALLET = "1YourBitcoinAddressHere"

NUM_WORDS = 12  # Atau 24, jika yakin
MAX_THREADS = 8  # Atur sesuai jumlah core CPU Anda

mnemo = Mnemonic("english")

# ---------------------- OPENCL SETUP ----------------------
def setup_opencl():
    platforms = cl.get_platforms()
    devices = platforms[0].get_devices()
    device = devices[0]
    context = cl.Context([device])
    queue = cl.CommandQueue(context, properties=cl.command_queue_properties.PROFILING_ENABLE)
    return context, queue, device

def load_program_source(filename):
    with open(filename, 'r') as f:
        return f.read()

def build_program(context, filename):
    source = load_program_source(filename)
    return cl.Program(context, source).build()

# ---------------------- ADDRESS DERIVATION ----------------------
def mnemonic_is_valid(mnemonic_phrase):
    return mnemo.check(mnemonic_phrase)

def derive_address_from_seed(seed_phrase):
    seed = mnemo.to_seed(seed_phrase, passphrase="")
    master_key = BIP32Key.fromEntropy(seed)
    return master_key.Address()

def test_mnemonic(candidate, context, queue, program):
    phrase = ' '.join(candidate)
    if not mnemonic_is_valid(phrase):
        return None
    try:
        derived_address = derive_address_from_seed(phrase)
        if derived_address == DESTINY_WALLET:
            return phrase
        else:
            return None
    except Exception:
        return None

# ---------------------- MAIN EXECUTION ----------------------
def main():
    print(f"[+] Starting brute-force with {len(CANDIDATE_WORDS)} words, targeting: {DESTINY_WALLET}")

    context, queue, device = setup_opencl()
    program = build_program(context, "./kernel/main.cl")

    total_combinations = itertools.combinations(CANDIDATE_WORDS, NUM_WORDS)
    executor = ThreadPoolExecutor(max_workers=MAX_THREADS)

    start = time.time()
    futures = []
    for combo in total_combinations:
        futures.append(executor.submit(test_mnemonic, combo, context, queue, program))

    for future in futures:
        result = future.result()
        if result:
            print(f"[✓] Found matching mnemonic!\n{result}")
            break

    end = time.time()
    print(f"[i] Brute-force finished in {end - start:.2f} seconds")

if __name__ == "__main__":
    main()
