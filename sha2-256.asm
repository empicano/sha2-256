
section .data
  ;; Usage message
  msg_usage       db    'usage: sha2-256 <value>', 0xa
  msg_usage_len   equ   $ - msg_usage
  ;; Initialize hash values
  i               dd    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ;; Initialize round constants
  k               dd    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2


section .bss
  chk             resd  64      ; current chunk in message iteration
  stt             resd  8       ; state of compression function (begins as copy of i)


section .text
  global _start                 ; entrypoint for the linker


_start:
  ;; Get first argument argv[1]
  pop   eax                     ; get number of program arguments
  cmp   eax, 2                  ; test if one argument
  jne   help                    ; if not equal, show usage message and exit
  pop   esi                     ; store program name argv[0] in esi
  pop   esi                     ; overwrite esi with first argument argv[1]

  ;; Compute the length of argv[1] and store in ecx
  mov   edi, esi                ; set edi to string argv[1]
  mov   ecx, -1                 ; set the max size of the string
  mov   eax, 0                  ; initialize eax with ascii NUL character
  cld
  repne scasb                   ; scan bytes in the string until we find the NUL character
  not   ecx                     ; get length of string
  dec   ecx                     ; decrement to account for read NUL character

  ;; Pad message
  call  pad

  ;; Extend and compress
  shr   ecx, 4                  ; number of chunks (each 16 dwords) to loop over
  xor   ebx, ebx                ; initiate loop counter
a0:
  call  extend
  call  compress
  inc   ebx
  cmp   ebx, ecx
  jne   a0

  ;; Print digest and exit
  mov   esi, i
  mov   ecx, 8
  call  print_memd
  jmp   exit


pad:
  ;; Padding function
  ;; Append a single 1 bit to original message of length l bits
  ;; Append k 0 bits where k is the minimum number >= 0 such that (l + 1 + k + 64) % 512 = 0
  ;; Append l as a 64-bit big-endian integer

  ;; Expects:
  ;; ecx: length of program argument string in bytes
  ;; esi: pointer to program argument string

  ;; TODO Realize endianness change on the fly when copying message
  ;; - eax komplett auf null setzen
  ;; - falls noch message übrig ist:
  ;; - nächstes byte von hinten reinladen so dass endianness gechanged wird, shl
  ;; - wenn nicht, bleibt das byte auf null, so wird gleich der pad auch gemacht

  ;; Calculate length of k and save to edx
  mov   eax, ecx
  and   eax, 0x3f               ; calculate length of program argument string % 64
  cmp   eax, 56
  jb    m0
  mov   edx, 119                ; k / 8 = 119 - r if result r of modulo operation is >= 56
  jmp   m1
m0:
  mov   edx, 55                 ; else k / 8 = 55 - r
m1:
  sub   edx, eax

  ;; Dynamically allocate memory
  mov   ebx, 0                  ; get pointer to the first block we are allocating
  mov   eax, 45                 ; system call number (brk)
  int   0x80
  mov   edi, eax                ; save pointer in edi
  mov   ebx, eax                ; copy pointer in ebx
  add   ebx, ecx                ; add number of bytes we want to allocate to pointer value
  add   ebx, edx
  add   ebx, 9
  mov   eax, 45
  int   0x80

  ;; Status:
  ;; ecx: length of program argument string in bytes
  ;; edx: length of needed zero pad in bytes
  ;; esi: address of program argument string
  ;; edi: pointer to allocated memory

  ;; Build padded message in newly allocated memory
  mov   eax, ecx                ; save program argument string length
  mov   ebx, edi                ; save pointer to allocated memory
  cld
  rep   movsb                   ; copy program argument string to allocated memory

  mov   [edi], byte 0x80        ; append a single 1 bit
  inc   edi

  mov   ecx, edx                ; save number of zero pad bytes in ecx
  add   ecx, 4
  mov   edx, eax
  mov   eax, 0                  ; save what to copy in eax
  cld
  rep   stosb                   ; zero padding

  ;; Status:
  ;; ebx: pointer to allocated memory
  ;; edx: length of program argument string
  ;; edi: pointer to allocated memory + eax + number of zero pad bytes

  shl   edx, 3
  mov   [edi], edx              ; save message length in bit as 64-bit value to end of pad
  add   edi, 4

  ;; Status:
  ;; ebx: pointer to allocated memory
  ;; edi: pointer to end of allocated memory

  mov   ecx, edi
  sub   ecx, ebx
  shr   ecx, 2
  mov   esi, ebx

  ;; Status
  ;; ecx: length of padded message in dwords
  ;; esi: pointer to padded message

  ;; Change endianness
  mov   edx, ecx
  dec   edx
m2:
  dec   edx
  mov   eax, [esi+edx*4]
  xchg  ah, al
  ror   eax, 16
  xchg  ah, al
  mov   [esi+edx*4], eax
  test  edx, edx
  jnz   m2

  ;; Status
  ;; ecx: length of padded message in dwords
  ;; esi: pointer to padded message

  ret


extend:
  ;; Extends message chunk from 16 dwords to 64 dwords, saved in chk

  ;; Expects:
  ;; ebx: counter in iteration of padded message (0 for 1. chunk, 1 for 2. chunk, ...)
  ;; esi: pointer to padded message

  pusha

	;; Copy 16 dwords from padded message to beginning of chunk
  mov   ecx, 16                 ; number of dwords to copy
  shl   ebx, 6
  add   esi, ebx                ; pointer to padded message
  mov   edi, chk                ; pointer to destination
  cld
  rep   movsd

  ;; Extend copied dwords to fill all 64 dwords of chunk
s0:
  mov   eax, [chk+ecx*4+4]      ; calculate s0 in eax
  mov   ebx, eax
  mov   edx, eax
  ror   eax, 7
  ror   ebx, 18
  shr   edx, 3
  xor   eax, ebx
  xor   eax, edx
  mov   ebx, [chk+ecx*4+56]     ; calculate s1 in ebx
  mov   edx, ebx
  mov   esi, ebx
  ror   ebx, 17
  ror   edx, 19
  shr   esi, 10
  xor   ebx, edx
  xor   ebx, esi
  add   eax, ebx                ; add up to next extension dword
  add   eax, [chk+ecx*4]
  add   eax, [chk+ecx*4+36]
  mov   [chk+ecx*4+64], eax
  inc   ecx
  cmp   ecx, 48                 ; counter runs from 0 to 47
  jnz   s0

  popa
  ret


compress:
  ;; Compression function

  pusha

  ;; Copy i to stt as initial state of compression function
  mov   ecx, 8
  mov   esi, i
  mov   edi, stt
  cld
  rep   movsd

  ;; Loop 64 times
  xor   ecx, ecx
p0:

  ;; Calculate major
  mov   eax, [stt]              ; load a
  mov   esi, eax
  mov   ebx, [stt+4]            ; load b
  mov   edx, [stt+8]            ; load c
  and   eax, ebx
  and   ebx, edx
  and   edx, esi
  xor   eax, ebx
  xor   eax, edx                ; store in eax

  ;; Calculate sigma 0
  mov   ebx, esi                ; remark that a is still in esi
  mov   edx, esi
  ror   ebx, 2
  ror   edx, 13
  ror   esi, 22
  xor   ebx, edx
  xor   ebx, esi                ; store in ebx

  ;; Calculate t2
  add   eax, ebx                ; store in eax

  ;; Calculate sigma 1
  mov   ebx, [stt+16]           ; load e
  mov   edx, ebx
  mov   esi, ebx
  mov   edi, ebx
  ror   ebx, 6
  ror   edx, 11
  ror   esi, 25
  xor   ebx, edx
  xor   ebx, esi                ; store in ebx

  ;; Calculate ch
  mov   edx, edi                ; remark that e is still in edi
  not   edx
  and   edi, [stt+20]           ; load f
  mov   esi, [stt+24]           ; load g
  and   edx, esi
  xor   edx, edi                ; store in edx

  ;; Calculate t1
  add   ebx, edx
  add   ebx, [stt+28]           ; load h
  add   ebx, [chk+ecx*4]
  add   ebx, [k+ecx*4]          ; store in ebx

  ;; Store new state
  mov   [stt+28], esi           ; remark that g is still in esi
  mov   edx, [stt+20]
  mov   [stt+24], edx
  mov   edx, [stt+16]
  mov   [stt+20], edx
  mov   edx, [stt+12]
  add   edx, ebx
  mov   [stt+16], edx
  mov   edx, [stt+8]
  mov   [stt+12], edx
  mov   edx, [stt+4]
  mov   [stt+8], edx
  mov   edx, [stt]
  mov   [stt+4], edx
  add   eax, ebx
  mov   [stt], eax

  inc   ecx
  cmp   ecx, 64
  jl    p0

  ;; Compute final digest of this round
  mov   edx, [stt]
  add   [i], edx
  mov   edx, [stt+4]
  add   [i+4], edx
  mov   edx, [stt+8]
  add   [i+8], edx
  mov   edx, [stt+12]
  add   [i+12], edx
  mov   edx, [stt+16]
  add   [i+16], edx
  mov   edx, [stt+20]
  add   [i+20], edx
  mov   edx, [stt+24]
  add   [i+24], edx
  mov   edx, [stt+28]
  add   [i+28], edx

  popa
  ret


print_memd:
  ;; Prints out memory segment as hex value (dword-wise, note little-endianness)
  ;; Expects:
  ;; ecx: length of memory segment in dwords
  ;; esi: pointer to memory segment

  pusha

  ;; Dynamically allocate memory
  mov   ebx, 0                  ; get pointer to the first block we are allocating
  mov   eax, 45                 ; system call number (brk)
  int   0x80
  mov   edi, eax                ; save pointer in edi
  mov   ebx, eax                ; copy pointer in ebx
  shl   ecx, 2
  add   ebx, ecx                ; add number of bytes we want to allocate to pointer value
  add   ebx, 1                  ; add one byte for new line character
  mov   eax, 45
  int   0x80                    ; call kernel

  ;; Build hex string
  mov   [edi+ecx*2], byte 0xa   ; move new line character into last byte of buffer
  shl   ecx, 1
  inc   ecx
  push  ecx	                    ; push buffer length to stack
  shr   ecx, 3
g0:
  dec   ecx
  mov   eax, [esi+ecx*4]        ; move next value from memory to eax
  mov   edx, 8                  ; set counter that loops over next 32-bit value to 8
g1:
  dec   edx                     ; decrement inner loop counter
  mov   ebx, eax                ; move eax to ebx to be able to work on it
  and   ebx, 0xf                ; get only last digit of hex value (last 4 bits)
  cmp   ebx, 10                 ; is value >= 9 ?
  jb    g2
  add   ebx, 0x27               ; if yes, add 0x57 to [10-15] to get byte value of ascii 'a'
g2:
  add   ebx, 0x30               ; if not, add 0x30 to [0-9] to get byte value of ascii '0'
  add   edi, edx
  mov   [edi+ecx*8], bl         ; copy next ascii byte value from ebx to buffer
  sub   edi, edx
  shr   eax, 4                  ; get next digit to be printed to the right of eax
  cmp   edx, 0                  ; iterate 8 times
  ja    g1
  test  ecx, ecx                ; iterate over dwords
  jnz   g0

  ;; Print buffer
  pop   edx                     ; buffer length to edx
  mov   ecx, edi                ; pointer to ecx
  mov   ebx, 1                  ; file descriptor (std_out) to ebx
  mov   eax, 4                  ; system call number (sys_write) to eax
  int   0x80                    ; call kernel

  popa
  ret                           ; return


print_memb:
  ;; Prints out memory segment as hex value (byte-wise, note little-endianness)
  ;; Expects:
  ;; ecx: length of memory segment in bytes
  ;; esi: pointer to memory segment

  pusha

  ;; Dynamically allocate memory
  mov   ebx, 0                  ; get pointer to the first block we are allocating
  mov   eax, 45                 ; system call number (brk)
  int   0x80
  mov   edi, eax                ; save pointer in edi
  mov   ebx, eax                ; copy pointer in ebx
  add   ebx, ecx                ; add number of bytes we want to allocate to pointer value
  add   ebx, ecx
  add   ebx, 1                  ; add one byte for new line character
  mov   eax, 45
  int   0x80                    ; call kernel

  ;; Build hex string
  xor   edx, edx                ; set loop counter to zero
e0:
  cmp   edx, ecx                ; did we already print whole memory segment?
  jz    e3
  mov   al, [esi+edx]           ; get next value from memory
  mov   bl, al                  ; copy value to bl
  shr   al, 4                   ; get the 4 bit from the upper half
  and   bl, 0xf                 ; get the 4 bit from the lower half
  cmp   al, 10                  ; is value >= 9?
  jb    e1
  add   al, 0x27                ; if yes, add 0x57 to [10-15] to get byte value of ascii [a-f]
e1:
  add   al, 0x30                ; if not, add 0x30 to [0-9] to get byte value of ascii [0-9]
  mov   [edi+edx*2], al         ; copy upper half ascii byte value to buffer
  cmp   bl, 10                  ; same for lower half, is value >= 9?
  jb    e2
  add   bl, 0x27                ; if yes, ...
e2:
  add   bl, 0x30                ; if not, ...
  mov   [edi+edx*2+1], bl       ; copy lower half ascii byte value to buffer
  inc   edx
  jmp   e0                      ; loop
e3:
  mov   [edi+edx*2], byte 0xa   ; move new line character into last byte of buffer
  shl   edx, 2
  inc   edx                     ; segment length to edx

  ;; Print buffer
  mov   ecx, edi                ; pointer to segment to write to ecx
  mov   ebx, 1                  ; file descriptor (std_out) to ebx
  mov   eax, 4                  ; system call number (sys_write) to eax
  int   0x80                    ; call kernel

  popa
  ret


help:
  ;; Prints usage message and exits
  mov   edx, msg_usage_len      ; message length to edx
  mov   ecx, msg_usage          ; message to write to ecx
  mov   ebx, 1                  ; file descriptor (std_out) to ebx
  mov   eax, 4                  ; system call number (sys_write) to eax
  int   0x80                    ; call kernel
  jmp   exit                    ; jump to exit label


exit:
  ;; Exit routine
  mov   ebx, 0                  ; exit status to ebx
  mov   eax, 1                  ; system call number (sys_exit) to eax
  int   0x80                    ; call kernel

