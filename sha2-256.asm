
section .data
  ;; Usage message
  msg_usage       db    'usage: sha2-256 <value>', 0xa
  msg_usage_len   equ   $ - msg_usage
  ;; Initialize hash values
  i               dd    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ;; Initialize round constants
  k               dd    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2


section .bss
  buf             resb  64      ; buffer for print_dig


section .text
  global _start                 ; entrypoint for the linker


_start:
  ;; Get first argument argv[1]
  pop   eax                     ; get number of program arguments
  cmp   eax, 2                  ; test if one argument
  jne   help                    ; if not equal, show usage message and exit
  pop   ebx                     ; store program name argv[0] in ebx
  pop   ebx                     ; overwrite ebx with first argument argv[1]

  ;; Compute the length of argv[1] and store in ecx
  mov   edi, ebx                ; set edi to string argv[1]
  mov   ecx, -1                 ; set the max size of the string
  mov   al, 0                   ; initialize al with ascii NUL character
  cld
  repne scasb                   ; scan bytes in the string until we find the null character
  not   ecx                     ; get length of string
  dec   ecx                     ; decrement to account for read NUL character

  ;; Print digest
  call  print_dig

  jmp   exit                    ; jump to exit label


pad:
  ;; SHA256 padding function
  ;; Append a single 1 bit to original message of length l bits
  ;; Append k 0 bits where k is the minimum number >= 0 such that (l + 1 + k + 64) % 1024 = 0
  ;; Append l as a 64-bit big-endian integer


compress:
  ;; SHA256 compression function
  ;; --> ror for rotate, shr for right shift


print_dig:
  ;; Prints digest array i as hex string to std_out
  push  eax                     ; save registers
  push  ebx
  push  ecx
  push  edx

  ;; Transforms values in i to ascii values and saves them in buffer
  xor   ecx, ecx                ; set counter that loops over i to 0
l0:
  mov   eax, [i+ecx*4]          ; move next value from memory to eax
  mov   edx, 8                  ; set counter that loops over next 32-bit value to 8
l1:
  dec   edx                     ; decrement inner loop counter
  mov   ebx, eax                ; move eax to ebx to be able to work on it
  and   ebx, 0xf                ; get only last digit of hex value (last 4 bits)
  cmp   ebx, 10                 ; is value >= 9 ?
  jb    m0
  add   ebx, 0x27               ; if yes, add 0x57 to [10-15] to get byte value of ascii 'a'
m0:
  add   ebx, 0x30               ; if not, add 0x30 to [0-9] to get byte value of ascii '0'
  mov   [buf+ecx*8+edx], bl     ; copy next ascii byte value from ebx to buffer
  shr   eax, 4                  ; get next digit to be printed to the right of eax
  cmp   edx, 0                  ; iterate 8 times
  ja    l1
  inc   ecx                     ; increment outer loop counter
  cmp   ecx, 8                  ; iterate 8 times
  jb    l0

  ;; Print buffer
  mov   edx, 64                 ; message length to edx
  mov   ecx, buf                ; message to write to ecx
  mov   ebx, 1                  ; file descriptor (std_out) to ebx
  mov   eax, 4                  ; system call number (sys_write) to eax
  int   0x80                    ; call kernel

  pop   edx                     ; recover registers
  pop   ecx
  pop   ebx
  pop   eax
  ret                           ; return


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

