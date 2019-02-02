
section .data
  ;; usage message
  msg_usage       db    'usage: sha2-256 <value>', 0xa
	msg_usage_len   equ   $ - msg_usage
  ;; initial hash values
  I               dd    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

section .bss
  ;; buffer for hex_print
  buff            resb  8

section .text
	global          _start        ; entrypoint for the linker

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

  mov   eax, ecx
  call  hex_print

  jmp   exit                    ; jump to exit label

pad:
  ;; SHA256 padding function
  ;; Append a single 1 bit to original message of length l bits
  ;; Append k 0 bits where k is the minimum number >= 0 such that (l + 1 + k + 64) % 1024 = 0
  ;; Append l as a 64-bit big-endian integer

compress:
  ;; SHA256 compression function
  ;; --> ror for rotate, shr for right shift

hex_print:
  ;; Prints value in eax as hex value
  push  eax                     ; save registers
  push  ebx
  push  ecx
  push  edx

  ;; loop in 8 steps over the 32 bit value
  mov   ecx, 8                  ; initialize loop counter
l0:
  mov   ebx, eax                ; move eax to ebx
  and   ebx, 0xf                ; get only last letter of hex value
  cmp   ebx, 10                 ; is value >= 9 ?
  jl    m0
  add   ebx, 0x27               ; if yes, add 0x57 to [10-15] get to ascii 'a'
m0:
  add   ebx, 0x30               ; if not, add 0x30 to [0-9] get to ascii '0'
  mov   [buff + ecx - 1], bl    ; save byte value in buffer
  shr   eax, 4                  ; shift eax by 4 to get next letter to the right
  loop  l0                      ; iterate

  ;; print all eight values in one go
  mov   edx, 8                  ; message length to edx
  mov   ecx, buff               ; message to write to ecx
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
  ;; exit routine
  mov   ebx, 0                  ; exit status to ebx
  mov   eax, 1                  ; system call number (sys_exit) to eax
	int   0x80                    ; call kernel

