#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import string
import re
import os
from pprint import pprint

alphabet = (string.lowercase + "åäö").decode('utf-8')
letter_frequency = {
	'A':9.38, 'B':1.54, 'C':1.49, 'D':4.70, 'E':10.15, 'F':2.03,
	'G':2.86, 'H':2.09, 'I':5.82, 'J':0.61, 'K':3.14,  'L':5.28,
	'M':3.47, 'N':8.54, 'O':4.48, 'P':1.84, 'Q':0.02,  'R':8.43,
	'S':6.59, 'T':7.69, 'U':1.92, 'V':2.42, 'W':0.14,  'X':0.16,
	'Y':0.71, 'Z':0.07, 'å':1.34, 'ä':1.80, 'ö':1.31
}

common_words = [[], [],
	['en', 'av', 'är', 'på', 'de', 'om', 'år'],
	['och', 'som', 'att', 'den', 'med', 'för', 'det', 'ett', 'han', 'var', 'har', 'vid', 'men', 'sig', 'man'],
	['till', 'från', 'även', 'inte'],
	['under', 'eller', 'efter']
]

# change from percents to fractions
tmp = {}
for k in letter_frequency:
	tmp[k.lower().decode('utf-8')] = letter_frequency[k]/100
letter_frequency = tmp
del tmp

def freq(s):
	d = {}
	for c in s:
		d[c] = d.get(c,0) + 1
	return d

def ns(n):
	return alphabet[n%len(alphabet)]
def sn(s):
	return alphabet.find(s)

def crypt(plain, key, crypt=1):
	L = []
	for c,i in zip(plain,range(len(plain))):
		L.append(ns(sn(c) + crypt*sn(key[i%len(key)])))
	return ''.join(L)
	
def decrypt(plain, key):
	return crypt(plain, key, -1)
	
def partial_decrypt(plain, key):
	return crypt(plain, key.replace(' ', 'a'), -1)
	
def partial_decrypt(plain, key, keylen):
	return crypt(plain, key + 'a' * (keylen-len(key)))
	
def crack(cipher):
	# guess key length
	# find each key char by freq analysis
	key = "CTHULHURLYEHWGAH".lower()
	return key
	
def kappa_o(cipher, m):
	IC = 0.
	for j in range(m):
		xj = cipher[j::m]
		f = freq(xj)
		ic = 0.
		for i in f.values():
			ic = ic + i*(i-1)
		l = len(xj)
		ic =  ic / (l * (l-1))
		IC = IC + ic
	IC = IC / m
	return IC

def dist(f1,f2):
	sqe = 0.
	for k,v in f1.items():
		sqe = sqe + (v - f2[k])**2
	return sqe/len(f1)
	
def get_key(cipher, keylen):
	key = ""
	for j in range(keylen):
		sqe = 10**8 # approx inf
		xj = cipher[j::keylen]
		k = 0
		for c in range(29):
			s = decrypt(xj,alphabet[c])
			d = dist(freq(s),letter_frequency)
				
			if d < sqe:
				sqe = d
				k = c
		key = key + alphabet[k]
	return key
		
def main():
	# example for help text
	prog = os.path.basename(__file__)
	examples = "examples:\n"
	examples+= "  " + prog + " -k mysecret plain.txt\n"
	examples+= "  " + prog + " -m decrypt -k mysecret cipher.txt"

	# setup command line arguments
	parser = argparse.ArgumentParser(
		description='Encryption and decryption using the Vigenère cipher, adapted for the Swedish alphabet.',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog=examples)
	parser.add_argument('-k', help="the secret key to use", dest="key")
	parser.add_argument('-m', default='encrypt', choices=['encrypt','decrypt','break'], help="use encryption (default), decryption, or attempt to break an encrypted text", dest="mode")
	parser.add_argument('infile', type=file, help="the file containing the plaintext (for encryption) or ciphertext (for decryption)")
	args = parser.parse_args()

	# read file
	intxt = args.infile.read()
	args.infile.close()

	# convert to lower case
	intxt = intxt.decode('utf-8').lower()

	# remove all non-alphanum characters
	r = re.compile(ur"[\W_]+", re.UNICODE)
	intxt = r.sub("", intxt)
	
	if args.mode == 'break':
		
		#key = crack(intxt)
		#plain = decrypt(intxt, key)
		#print plain.upper()
		letter_frequency
		sum = 0
		keylen_distr = []
		for m in range(1,16+1):
			keylen_distr.append((m, kappa_o(intxt, m)))
		
		keylen_distr.sort(lambda x,y: cmp(x[1],y[1]))
		#pprint(keylen_distr)
		keylen = keylen_distr[-1][0]
		print "keylen:",keylen
		key = get_key(intxt,keylen)
		print "key:", key
		print "plaintext:", decrypt(intxt,key)
		
	else:
		# the encryption key
		if args.key is None:
			print "you need to specify a key"
			exit()
		key = args.key.decode('utf-8').lower()
	
		mode = 1 if args.mode == 'encrypt' else -1
	
		outtxt = crypt(intxt, key, mode).upper()
		print outtxt
	
		#pre = "vig_group2."
		#f = open(pre+"crypto", "w")
		#f.write(outtxt.encode('utf-8'))
		#f.close()
		#f = open(pre+"plain", "w")
		#f.write(intxt.encode('utf-8'))
		#f.close()
		#f = open(pre+"key", "w")
		#f.write(key.encode('utf-8'))
		#f.close()
		

	
if __name__ == '__main__':
	global kappa_r, kappa_p
	kappa_p = 1/29.
	kappa_r = 0
	for f in letter_frequency.values():
		kappa_r = kappa_r + f**2
	
	
	main()
