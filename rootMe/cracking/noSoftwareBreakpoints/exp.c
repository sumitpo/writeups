// gcc exp.c -o exp

#include <stdio.h>
unsigned char arr[] = {0x1e, 0xcd, 0x2a, 0xd5, 0x34, 0x87, 0xfc, 0x78, 0x64,
                       0x35, 0x9d, 0xec, 0xde, 0x15, 0xac, 0x97, 0x99, 0xaf,
                       0x96, 0xda, 0x79, 0x26, 0x4f, 0x32, 0xe0};
int main() {
  long edx = 0xAC77E166;
  for (int i = 24; i >= 0; i--) {
    unsigned char dl = ((edx >> (i + 1)) & 0xff);
    unsigned char al = arr[24 - i];
    /*
    printf("edx is %08x\n", (edx >> (i + 1)));
    printf("dl is %02x, ", dl);
    printf("al is %02x, ", al);
    printf("%02x ", dl ^ al);
    */
    printf("%c", dl ^ al);
  }
  printf("\n");
  return 1;
}
