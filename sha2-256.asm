
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

  ;; Print digest and exit
  %if 0
  mov   esi, i
  mov   ecx, 8
  call  print_memd
  %endif

  jmp   exit


compress:
  ;; SHA256 compression function
  ;; Expects counter value to know position (0-63) in chunk and k in ecx
  push  eax
  push  ebx
  push  edx
  push  ecx

  ;; Calculate major
  mov   eax, [stt]
  mov   edx, eax
  mov   ebx, [stt+1*4]
  mov   ecx, [stt+2*4]
  and   eax, ebx
  and   ebx, ecx
  and   ecx, edx
  xor   eax, ebx
  xor   eax, ecx                ; store in eax

  ;; Calculate sigma 0
  mov   ebx, edx                ; remark that [stt] is still in edx
  mov   ecx, edx
  ror   ebx, 2
  ror   ecx, 13
  ror   edx, 22
  xor   ebx, ecx
  xor   ebx, edx                ; store in ebx

  ;; Calculate t2
  add   eax, ebx                ; store in eax

  ;; Calculate sigma 1
  mov   ebx, [stt+4*4]
  mov   ecx, ebx
  mov   edx, ebx
  ror   ebx, 6
  ror   ecx, 11
  ror   edx, 25
  xor   ebx, ecx
  xor   ebx, edx                ; store in ebx

  ;; Calculate ch
  mov   ecx, [stt+4*4]
  mov   edx, ecx
  not   ecx
  and   ecx, [stt+6*4]
  and   edx, [stt+5*4]
  xor   ecx, edx                ; store in ecx

  ;; Calculate t1
  add   ebx, edx
  add   ebx, [stt+7*8]
  pop   ecx                     ; get counter from stack
  add   ebx, [chk+ecx*4]
  add   ebx, [k+ecx*4]          ; store in ebx

  ;; Store new compression state in memory
  mov   edx, [stt+6*8]
  mov   [stt+7*8], edx
  mov   edx, [stt+5*8]
  mov   [stt+6*8], edx
  mov   edx, [stt+4*8]
  mov   [stt+5*8], edx
  mov   edx, [stt+3*8]
  add   edx, ebx
  mov   [stt+4*8], edx
  mov   edx, [stt+2*8]
  mov   [stt+3*8], edx
  mov   edx, [stt+1*8]
  mov   [stt+2*8], edx
  mov   edx, [stt]
  mov   [stt+1*8], edx
  add   eax, ebx
  mov   [stt], eax

  ;; recover registers
  pop   edx
  pop   ebx
  pop   eax
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

