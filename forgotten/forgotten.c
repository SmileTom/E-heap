#include <stdio.h>
int main() {
  void *a, *b, *c, *b1, *b2, *big;
  a = malloc(0x108);
  b = malloc(0x200);
  c = malloc(0x108);

  free(b);
  memset(a,0,0x109);
  b1 = malloc(0x80);
  b2 = malloc(0x80);
  strcpy(b2, "KY-THUAT-TAN-CONG-FORGOTTEN CHUNK");
  printf("DATA VICTIM: %s\n",b2);
  free(b1);
  free(c);
  big = malloc(0x200);
  memset(big, 0x41, 0x200 - 1);
  printf("DATA VICTIM: %s\n", (char *)b2);
  return 0;
}