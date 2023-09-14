from sage.all import *
from pwn import *
import json
from Crypto.Util.number import long_to_bytes


# dimension
n = 64
# plaintext modulus
p = 257
# ciphertext modulus
q = 0x10001

V = VectorSpace(GF(q), n)


io = remote('socket.cryptohack.org', 13411)

def json_send(hsh):
    request = json.dumps(hsh).encode()
    io.sendline(request)

received = io.recvline()
print(received)

A_matrix = []
B_matrix = []
for m in range(n): #need n=dimV equations to solve linear system
	to_send = {"option" : "encrypt", "message": m}
	json_send(to_send)
	rcv = json.loads(io.recvline().decode())

	A = rcv["A"][1:-1]
	A_list = A.split(",")

	b = int(rcv["b"])
	A_matrix.append(A_list)
	B_matrix.append(b-m)
	

AA = matrix(GF(q),A_matrix)
BB = matrix(GF(q),B_matrix).transpose()	
S = AA.solve_right(BB)


i=0
flag= b""
while(True):
	to_send = {"option" : "get_flag", "index": i}
	try:
		json_send(to_send)
		rcv = json.loads(io.recvline().decode())
		A = rcv["A"][1:-1]
	except:
		print(flag)
		break
	A_list = A.split(",")
	A = V(A_list)
	AS = int(str(A*S)[1:-1])
	b = int(rcv["b"])
	m = b - AS
	flag += long_to_bytes(m)
	i+=1
	
	
	









