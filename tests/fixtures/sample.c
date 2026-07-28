/* GhostBin test fixture: small, deterministic, keeps its symbol table. */

int add(int a, int b) {
    return a + b;
}

int max2(int a, int b) {
    if (a > b) {
        return a;
    }
    return b;
}

static int square(int x) {
    return x * x;
}

int main(void) {
    return add(1, 2) + max2(3, 4) + square(5);
}
