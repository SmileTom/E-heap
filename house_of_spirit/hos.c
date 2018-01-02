#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct fast_chunk {
  size_t prev_size;
  size_t size;
  struct fast_chunk *fd;
  struct fast_chunk *bk;
  char buf[0x20];               // fastbin size range
};

int main() {
  struct fast_chunk fake_chunks[2]; 
  void *ptr, *victim;
  ptr = malloc(0x30);
  printf("%p\n", &fake_chunks[0]);
  printf("%p\n", &fake_chunks[1]);
  fake_chunks[0].size = sizeof(struct fast_chunk);
  fake_chunks[1].size = sizeof(struct fast_chunk);
  ptr = (void *)&fake_chunks[0].fd;
  free(ptr);
  victim = malloc(0x30);
  printf("%p\n", victim);
  return 0;
}