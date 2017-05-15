import sys, string
tcharset = string.lowercase + ' ,:.'
kcharset = [chr(x) for x in range(32,48) + range(58,65) + range(91,97) + range(123,127)]
for linea in sys.stdin:
	print ''.join([kcharset[tcharset.index(x)] for x in linea])