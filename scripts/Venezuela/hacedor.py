import sys, string
tcharset = string.lowercase + ' ,:.'
kcharset = [chr(x) for x in range(32,48) + range(58,65) + range(91,97) + range(123,127)]
file = 'secreto_e47cadcff56cdcf8cb27eccb61dec09f.txt'
h = open(file, "r")

out='' 
for linea in h.readline():
	#print ''.join([tcharset[kcharset.index(x)] for x in linea])
	out+=''.join([tcharset[kcharset.index(x)] for x in linea])

print out 



