#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import string
import re
import os
import sys
import codecs
from pprint import pprint

# the lower case alphabet, used to map between index and char
alphabet = (string.lowercase + "åäö").decode('utf-8')

# the normal letter frequency for swedish texts taken from
# http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/swedish-letter-frequencies/
letter_frequency = {
	u'a':0.0938, u'b':0.0154, u'c':0.0149, u'd':0.0470, u'e':0.1015,
	u'f':0.0203, u'g':0.0286, u'h':0.0209, u'i':0.0582, u'j':0.0061,
	u'k':0.0314, u'l':0.0528, u'm':0.0347, u'n':0.0854, u'o':0.0448,
	u'p':0.0184, u'q':0.0002, u'r':0.0843, u's':0.0659, u't':0.0769,
	u'u':0.0192, u'v':0.0242, u'w':0.0014, u'x':0.0016, u'y':0.0071,
	u'z':0.0007, u'å':0.0134, u'ä':0.0180, u'ö':0.0131
}

# output handle for printing proper utf-8
out = codecs.getwriter('utf-8')(sys.stdout)

# returns a dictionary with occurences of each character in the text s
def freq(s):
	d = {}
	for c in s:
		d[c] = d.get(c,0) + 1#./len(s) # this should not be out commented when doing the mean square error checking, but doing it this way improves the results for some weird reason.
	return d

# convert an index to a character
def ns(n):
	return alphabet[n%len(alphabet)]
	
# converts a character to an index
def sn(s):
	return alphabet.find(s)

# encrypts the text plain by shifting each character using the
# corresponding character index in the key multiplied by crypt
#
# in effect: crypt=1 => encryption, crypt=-1 => decryption
def crypt(plain, key, crypt=1):
	L = []
	for c,i in zip(plain,range(len(plain))):
		L.append(ns(sn(c) + crypt*sn(key[i%len(key)])))
	return ''.join(L)
	
# decrypt the text cipher using the key key.
def decrypt(cipher, key):
	return crypt(cipher, key, -1)
	
# calculate kappa_o for a key of length m using the cipher text cipher
def kappa_o(cipher, m):
	IC = 0.
	for j in range(m):
		xj = cipher[j::m]
		f = freq(xj)
		ic = 0.
		for v in f.values():
			i = v#*len(xj) # see freq()
			ic = ic + i*(i-1)
		l = len(xj)
		ic =  ic / (l * (l-1))
		IC = IC + ic
	IC = IC / m
	return IC

# return the mean squared error between two frequency distributions
def dist(f1,f2):
	sqe = 0.
	for k,v in f1.items():
		sqe = sqe + (v - f2[k])**2
	return sqe/len(f1)
	
# guess the key length for the encrypted text cipher by minimizing the
# distance of the frequency distribution
def get_keylen(cipher, minlen, maxlen):
	sum = 0
	keylen_distr = []
	for m in range(minlen,maxlen+1):
		keylen_distr.append((m, kappa_o(cipher, m)))
	keylen_distr.sort(lambda x,y: cmp(x[1],y[1]))
	return keylen_distr[-1][0]
	
# guess the key length for several cipher texts
def get_keylens(ciphers, minlen, maxlen):
	lengths = []
	for cipher in ciphers:
		lengths.append(get_keylen(cipher,minlen,maxlen))
	return lengths

# guess the key of length keylen for the encrypted text cipher by
# finding the characters which creates a frequency distribution in
# the plain text with the least distance from the standard frequency
# distribution for the target language.
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
	examples+= "  " + prog + " -m decrypt -k mysecret cipher.txt\n"
	examples+= "  " + prog + " -m break cipher.txt\n"
	examples+= "  " + prog + " -m break -min-len 16 -max-len 50 cipher1.txt cipher2.txt"

	# setup command line arguments
	parser = argparse.ArgumentParser(
		description='Encryption and decryption using the Vigenère cipher, adapted for the Swedish alphabet.',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog=examples)
	parser.add_argument('-m', default='encrypt', choices=['encrypt','decrypt','break'], help="use encryption (default), decryption, or attempt to break an encrypted text", dest="mode")
	parser.add_argument('-k', help="the secret key to use (not used while breaking)", dest="key")
	parser.add_argument('-min-len', help="the minimum length of the key (used while breaking)[default: 1]", dest="min_keylen", default=1, type=int)
	parser.add_argument('-max-len', help="the maximum length of the key (used while breaking)[default: 16]", dest="max_keylen", default=16, type=int)
	parser.add_argument('infile', type=file, help="the file containing the plaintext (for encryption) or ciphertext (for decryption)", nargs='+')
	args = parser.parse_args()
	
	# attempt to crack an encrypted text
	if args.mode == 'break':

		if args.min_keylen > args.max_keylen - 2:
			print "minimum key length must be at least two less than maximum key length."
			exit(0)
			
		intxts = []
		
		# read files
		for infile in args.infile:
			intxt = infile.read()
			infile.close()
			
			# convert to lower case
			intxt = intxt.decode('utf-8').lower()

			# remove all non-alphanum characters
			r = re.compile(ur"[\W_]+", re.UNICODE)
			intxt = r.sub("", intxt)
			
			intxts.append(intxt)
			
		# calculate kappa_o or each possible key length
		sum = 0
		keylen_distr = []
		for keylen in range(args.min_keylen, args.max_keylen+1):
			txt = ""
			for intxt in intxts:
				txt += intxt + (keylen - (len(intxt) % keylen)) * 'a'
			keylen_distr.append((keylen, kappa_o(txt, keylen)))
			
		# find the key length which yields the lowest kappa_o
		keylen_distr.sort(lambda x,y: cmp(x[1],y[1]))
		keylen = keylen_distr[-1][0]
		print "keylen:",keylen
		
		# concat the cipher texts by padding them
		txt = ""
		for intxt in intxts:
			txt += intxt + (keylen - (len(intxt) % keylen)) * 'a'
			
		# guess the key
		key = get_key(txt,keylen)
		
		# print result
		# TODO: should change to out.write so we can pipe it!
		print "key:", key
		for intxt in intxts:
			print "\n", decrypt(intxt,key)
		
	# either decrypt or encrypt a given text using a given key
	else:

		# read file
		for infile in args.infile:
			intxt = infile.read()
			infile.close()
			
			# convert to lower case
			intxt = intxt.decode('utf-8').lower()

			# remove all non-alphanum characters
			r = re.compile(ur"[\W_]+", re.UNICODE)
			intxt = r.sub("", intxt)
			
			# the encryption key
			if args.key is None:
				print "you need to specify a key"
				exit()
			key = args.key.decode('utf-8').lower()
		
			mode = 1 if args.mode == 'encrypt' else -1
		
			outtxt = crypt(intxt, key, mode).upper()
			outtxt = outtxt.lower() if mode == -1 else outtxt.upper()
			
			if len(args.infile) > 1:
				print "\n" + infile.name + ":"
			
			out.write(outtxt)
		

	
if __name__ == '__main__':
	
	# define some default kappa factors for the swedish language.
	global kappa_r, kappa_p
	kappa_p = 1/29.
	kappa_r = 0
	for f in letter_frequency.values():
		kappa_r = kappa_r + f**2
	
	main()
