import pyopencl as cl
import numpy as np
from mnemonic import Mnemonic
import hashlib
import time

# ====== Konfigurasi ======
ADDRESS_TARGET = "1K4ezpLybootYF23TM4a8Y4NyP7auysnRo"
WORDLIST_PATH = "text.txt"
WORDS_IN_MNEMONIC = 12

# Load wordlist subset
with open(WORDLIST_PATH) as f:
    word_subset = [w.strip() for w in f.readlines() if w.strip()]
subset_len = len(word_subset)
print(f"Loaded {subset_len} words from subset")

# Setup OpenCL
ctx = cl.create_some_context()
queue = cl.CommandQueue(ctx, properties=cl.command_queue_properties.PROFILING_ENABLE)

# Load OpenCL kernel
with open("main.cl") as f:
    kernel_src = f.read()
program = cl.Program(ctx, kernel_src).build()
kernel = program.verify

# Global size: brute-force N combinations
BRUTE_WORDS = 2  # Ubah ke 12 untuk pencarian penuh
total_combinations = subset_len ** BRUTE_WORDS
print(f"Brute-forcing {total_combinations} combinations of {BRUTE_WORDS} words")

# Siapkan buffers
mf = cl.mem_flags
full_wordlist = Mnemonic("english").wordlist
subset_indices = np.array([full_wordlist.index(w) for w in word_subset], dtype=np.uint16)
subset_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=subset_indices)
output_buf = cl.Buffer(ctx, mf.WRITE_ONLY, size=WORDS_IN_MNEMONIC * 2)

# Set kernel args
kernel.set_args(subset_buf, np.uint32(subset_len), np.uint64(total_combinations), output_buf)

# Jalankan kernel
global_size = (total_combinations,)
local_size = None

start = time.time()
event = cl.enqueue_nd_range_kernel(queue, kernel, global_size, local_size)
event.wait()
elapsed = time.time() - start
print(f"OpenCL kernel selesai dalam {elapsed:.2f} detik")

# Baca hasil
result = np.empty(WORDS_IN_MNEMONIC, dtype=np.uint16)
cl.enqueue_copy(queue, result, output_buf)

# Konversi hasil ke mnemonic
if np.all(result == 0):
    print("Tidak ditemukan kombinasi valid.")
else:
    mnemo = Mnemonic("english")
    phrase = ' '.join([full_wordlist[i] for i in result])
    print(f"Mnemonic ditemukan: {phrase}")
    seed = mnemo.to_seed(phrase)
    import bip32utils
    key = bip32utils.BIP32Key.fromEntropy(seed)
    addr = key.Address()
    print("Derived address:", addr)
    if addr == ADDRESS_TARGET:
        print("✅ ADDRESS MATCH!")
    else:
        print("❌ Address mismatch.")
