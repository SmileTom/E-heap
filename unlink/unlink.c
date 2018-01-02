#include <stdio.h>

unsigned int *chunk[2]; //&chunk=0x0804a02c
int main () {
  chunk[0] = (char *)malloc(0x80);
  chunk[1] = (char *)malloc(0x80);
  //0x804a02c <chunk>:	0x0804b008	0x0804b090
  // Tạo chunk giả tại vùng dữ liệu (metadata) của chunk
  // Cần khởi tạo con trỏ FD và BK cho chunk giả để bypass qua cơ  chế kiểm tra an ninh trong MACRO unlink
  // Kịch bản heap overflow, tiếp theo sửa trường header của chunk[1] để bypass kiểm tra an ninh
  gets(chunk[0]);// tràn bộ đệm heap khi sử dụng hàm kém an toàn gets
  // Khi chunk[1] freed thì unlink xảy ra với chunk được giả mạo(P)
  // Kết quả là chunk[0] sẽ trỏ tới &chunk[0]-3
  //0x804a02c <chunk>:	0x0804a020	0x0804b090
  //                        |         |
  //			              chunk[0]	  chunk[1]
  free(chunk[1]);
  gets(chunk[0]); // Có quyền ghi vào địa chỉ 0x0804a020
  printf ("chunk[0]:%p\n",chunk[0]);
  return 0;
}
