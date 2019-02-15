This project realizes the SHA2 cryptographic hash function for Linux in NASM syntax IA-32 assembly. An explanation with pseudocode of SHA2 can be found on [Wikipedia](https://en.wikipedia.org/wiki/SHA-2).

I intended it mostly as an assembly programming exercise, whilst also wanting to know how a hash function works on the inside. I had no real aspirations for extraordinary performance. I worked my way down from pseudocode to an implementation in Python, followed by a translation of the latter to assembly code.

**Assemble and run with:**

- `nasm -f elf32 sha2-256.asm -o sha2-256.o`
- `ld -m elf_i386 sha2-256.o -o sha2-256`
- `./sha-256 <string to hash>`

The assembly version as well as the Python version expect ascii strings as input.

