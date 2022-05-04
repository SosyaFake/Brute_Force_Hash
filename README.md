# **Brute Force Hash** and integration with **hashcat**.

# **Work's only on Win/Linxus OS!**

---

## What you need:

1. Python version > 3.0
2. tqdm for python (<pip install tqdm>)
3. hashcat (if you are linux user ```sudo apt install hashcat``` / if you are windows user download hashcat to <PATH_TO_BFH/hashcat>)

Hashcat GPU Driver requirements:
 - AMD GPUs on Linux require "RadeonOpenCompute (ROCm)" Software Platform (3.1 or later)
 - AMD GPUs on Windows require "AMD Radeon Adrenalin 2020 Edition" (20.2.2 or later)
 - Intel CPUs require "OpenCL Runtime for Intel Core and Intel Xeon Processors" (16.1.1 or later)
 - NVIDIA GPUs require "NVIDIA Driver" (440.64 or later) and "CUDA Toolkit" (9.0 or later)


## How to install:

1. Download archive / git clone https://github.com/SosyaFake/Brute_Force_Hash.git
2. Unpack archive / skip
3. Open command-line
4. Open main.py in command-line
5. Use
6. ...
7. Profit. (Check <output_files/output_cracked_hashes.txt>)

---

## Features:

1. You can Brute Force Hash with self-made dictionary or your's dictionary. (md5, sha1, sha256, sha224, sha384, sha512) with/out salt

2. You can generate Rainbow-Tables with your hashes (md5, sha1, sha256, sha224, sha384, sha512)

-  md5(sha1($pass).md5($pass).sha1($pass))
-  sha1(md5(md5($pass)))
-  etc.

3. You can use Brute Force with hashcat integration only with (md5, sha1, sha256, sha224, sha384, sha512) **without salt**


---

``` Very sh*tty code 👎 @SosyaFake  ```
