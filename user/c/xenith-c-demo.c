/* Built into /bin/c-demo by xenith-cc, xenith-asm, and xenith-ld. */
int main(void) {
    long remaining = 2;

    while (remaining > 0) {
        puts("XENITH_C_TOOLCHAIN_OK\n");
        remaining = remaining - 1;
    }

    if (remaining != 0) {
        return 1;
    } else {
        return 0;
    }
}
