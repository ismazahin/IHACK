/*
 * vuln_bof.c - DELIBERATELY VULNERABLE practice target for exploit_bof.py.
 *
 * Classic ret2win: fixed 64-byte buffer, no bounds check, and a win() that
 * prints the flag but is never called in normal flow.
 *
 * BUILD (no canary, no PIE so addresses are fixed - matches the exploit):
 *     gcc -fno-stack-protector -no-pie -o vuln_bof vuln_bof.c
 *
 * Make a flag for win() to print:
 *     echo 'FLAG{st4ck_sm4sh_ret2w1n}' > flag.txt
 *
 * SERVE over the network so pwntools remote() can reach it (socat is on the pwnbox):
 *     socat TCP-LISTEN:9001,reuseaddr,fork EXEC:./vuln_bof
 *
 * ATTACK from another terminal:
 *     # First find OFFSET and WIN_ADDR by hand (see exploit_bof.py header), then:
 *     python3 ../exploit_bof.py 127.0.0.1 9001
 *     # expected:  [bof] 127.0.0.1:9001 -> FLAG{st4ck_sm4sh_ret2w1n}
 *
 * Find the numbers:
 *     nm vuln_bof | grep win            # -> WIN_ADDR
 *     gdb ./vuln_bof  (cyclic / cyclic -l)   # -> OFFSET (should be 72)
 *
 * DO NOT deploy this anywhere real - it is intentionally insecure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    // The target of our overflow: prints the flag.
    system("cat flag.txt");
}

void vuln() {
    char buf[64];
    puts("Enter your name:");
    fflush(stdout);
    gets(buf);          // <-- THE VULNERABILITY: no bounds check, overflows buf
    printf("Hi, %s\n", buf);
    fflush(stdout);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    vuln();
    return 0;
}
