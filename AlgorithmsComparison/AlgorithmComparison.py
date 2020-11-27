#!usr/bin/env python
#_*_ coding: utf8 _*_

import os
import hashlib
import time
import sha3
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import *
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Signature import pss
from ecdsa import SigningKey, NIST521p

def AesVectorInput(input_file):
	lines  = [line.rstrip('\n') for line in open(input_file)]
	key   = [line[31:] for line in lines if 'key=' in line]
	plaintext  = [line[31:] for line in lines if 'plain=' in line]
	return [[key[i], plaintext[i]] for i in range(len(key))]

def HashVectorInput(input_file):
	lines  = [line.rstrip('\n') for line in open(input_file)]
	message = [line[31:].strip('\"') for line in lines if 'message=' in line]
	return message

def DsaVectorInput(input_file):
	lines  = [line.rstrip('\n') for line in open(input_file)]
	message = [line[26:].strip('\"": ') for line in lines if 'message = ' in line]
	k = [line[7:].strip('\"') for line in lines if 'k = ' in line]
	mode = [line[8:].strip(',mesag=":') for line in lines if 'With ' in line]
	return [[message[i], k[i], mode[i]] for i in range(len(message))]

def AES_ECB(vector,k):
	key, plaintext = [],[]
	cipherTime, decipherTime = [],[]
	for i in range(len(vector)):
		for j in range(len(vector[i])):
			key = vector[i][k]
			plaintext = vector[i][k + 1]
		plaintext = bytearray.fromhex(vector[i][k + 1])
		key = bytearray.fromhex(vector[i][k])

		initialTimeC = time.perf_counter()
		cipher = AES.new(key, AES.MODE_ECB)
		msg = cipher.encrypt(plaintext)
		elapsedTime = time.perf_counter() - initialTimeC
		cipherTime.append(elapsedTime)
		
		initialTimeD = time.perf_counter()
		decipher = AES.new(key, AES.MODE_ECB)
		decipher.decrypt(msg)
		elapsedTimeD = time.perf_counter() - initialTimeD
		decipherTime.append(elapsedTimeD)
	return cipherTime, decipherTime

def AES_CBC(vector,k):
	key, plaintext = [],[]
	cipherTime, decipherTime = [],[]
	iv =  b"\x00"*16
	for i in range(len(vector)):
		for j in range(len(vector[i])):
			key = vector[i][k]
			plaintext = vector[i][k + 1]
		key = bytearray.fromhex(vector[i][k])
		plaintext = bytearray.fromhex(vector[i][k + 1])
		
		initialTimeC = time.perf_counter()
		cipher = AES.new(key, AES.MODE_CBC, iv)
		message = cipher.encrypt(plaintext)
		elapsedTime = time.perf_counter() - initialTimeC
		cipherTime.append(elapsedTime)

		initialTimeD = time.perf_counter()
		decipher = AES.new(key, AES.MODE_CBC, iv)
		decipher.decrypt(message)
		elapsedTimeD = time.perf_counter() - initialTimeD
		decipherTime.append(elapsedTimeD)
	return cipherTime, decipherTime

def shaAlgorithms(mode,vectors,number):
	shaTimes = []
	vectores = HashVectorInput(vectors)
	for i in range(len(vectores)):
		if vectores[i] == "million":
			vectores[i] = 'a' * 1000000
		plaintext = bytearray(vectores[i], 'utf-8')
		if mode == 1:
			t = time.perf_counter()
			h = hashlib.sha384(plaintext)
			elapsedTime = time.perf_counter() - t
			shaTimes.append(elapsedTime)
			diggest = h.digest().hex().upper()
			print("Hash SHA384:", diggest)
		elif mode == 2:
			t = time.perf_counter()
			h = hashlib.sha512(plaintext)
			elapsedTime = time.perf_counter() - t
			shaTimes.append(elapsedTime)
			diggest = h.digest().hex().upper()
			print("Hash SHA512:", diggest)
		elif mode == 3:
			t = time.perf_counter()
			h = sha3.sha3_384(plaintext)
			elapsedTime = time.perf_counter() - t
			shaTimes.append(elapsedTime)
			diggest = h.digest().hex().upper()
			print("Hash SHA3_384:", diggest)
		elif mode == 4:
			t = time.perf_counter()
			h = sha3.sha3_512(plaintext)
			elapsedTime = time.perf_counter() - t
			shaTimes.append(elapsedTime)
			diggest = h.digest().hex().upper()
			print("Hash SHA3_512:", diggest)

	for n in range(0, number//8):
		plaintext=(b'\x00')*n
		if mode == 1:
			t = time.perf_counter()
			h = hashlib.sha384(plaintext)
			elapsedTime = time.perf_counter() - t
			shaTimes.append(elapsedTime)
			diggest = h.digest().hex().upper()
		if mode == 2:
			t = time.perf_counter()
			h = hashlib.sha512(plaintext)
			elapsedTime = time.perf_counter() - t
			shaTimes.append(elapsedTime)
			diggest = h.digest().hex().upper()
		if mode == 3:
			t = time.perf_counter()
			h = sha3.sha3_384(plaintext)
			elapsedTime = time.perf_counter() - t
			shaTimes.append(elapsedTime)
			diggest = h.digest().hex().upper()
		if mode == 4:
			t = time.perf_counter()
			h = sha3.sha3_512(plaintext)
			elapsedTime = time.perf_counter() - t
			shaTimes.append(elapsedTime)
			diggest = h.digest().hex().upper()
	return shaTimes

def RSA_OAEP():	
	message = Random.get_random_bytes(64)
	key = RSA.generate(1024)
	
	#Proceso de cifrado
	initialTimeC = time.perf_counter()
	cipher = PKCS1_OAEP.new(key)
	ciphertext = cipher.encrypt(message)
	elapsedTime = time.perf_counter() - initialTimeC
	
	#Proceso de descifrado
	initialTimeD = time.perf_counter()
	original = cipher.decrypt(ciphertext)
	elapsedTimeD = time.perf_counter() - initialTimeD
	return elapsedTime,elapsedTimeD

def RSA_PSS():
	message = Random.get_random_bytes(64)
	key = RSA.generate(1024)

	#Sign process
	signatureStart = time.perf_counter()
	h = SHA256.new(message)
	signature = pss.new(key).sign(h)
	signatureFinish = time.perf_counter() - signatureStart

	#Verifying the signature
	verifyingStart = time.perf_counter()
	h = SHA256.new(message)
	verifier = pss.new(key)
	try:
		verifier.verify(h, signature)
		print ("Authenticated Signature")
	except (ValueError, TypeError):
		print ("Unauthenticated Signature")
	verifyingFinish = time.perf_counter() - verifyingStart
	return signatureFinish, verifyingFinish

def DSA_alg(vector,n):
	key, plaintext = [],[]
	signatureTime, verificationTime = [],[]
	for i in range(len(vector)):
		for j in range(len(vector[i])):
			plaintext = vector[i][n]
			k = vector[i][n + 1]
			mode = vector[i][n + 2]
		message = bytes(plaintext, 'utf-8')
		key = DSA.generate(1024)
		k_int = int(k, 16)

		if (mode.startswith('SHA-1')):
			h = SHA.new(message)
		elif (mode.startswith('SHA-224')):
			h = SHA224.new(message)
		elif (mode.startswith('SHA-256')):
			h = SHA256.new(message)
		elif (mode.startswith('SHA-384')):
			h = SHA384.new(message)
		elif (mode.startswith('SHA-512')):
			h = SHA512.new(message)

		signatureStart = time.perf_counter()
		signer = DSS.new(key, 'fips-186-3')
		sign = signer.sign(h)
		signatureFinish = time.perf_counter() - signatureStart
		signatureTime.append(signatureFinish)
		verifyingStart = time.perf_counter()
		try:
			verifier = DSS.new(key, 'fips-186-3')
			verifier.verify(h, sign)
			print ("Authenticated Signature")
		except:
			print ("Unauthenticated Signature")
		verifyingFinish = time.perf_counter() - verifyingStart
		verificationTime.append(verifyingFinish)
	return signatureTime, verificationTime

def ecdsa_alg(vectores):
	signatureTime, verificationTime = [],[]
	palabras = HashVectorInput(vectores)
	for i in range(len(palabras)):
		message = bytearray(palabras[i], 'utf-8')
		sk = SigningKey.generate(curve=NIST521p)
		vk = sk.verifying_key
		signatureStart = time.perf_counter()
		signature = sk.sign(message)
		signatureFinish = time.perf_counter() - signatureStart
		signatureTime.append(signatureFinish)
		verifyingStart = time.perf_counter()
		try:
			assert vk.verify(signature,message)
			print ("Authenticated Signature")
		except:
			print ("Unauthenticated Signature")
		verifyingFinish = time.perf_counter() - verifyingStart
		verificationTime.append(verifyingFinish)
	return signatureTime, verificationTime

def table():
	print('\n\n\t				      RUNTIME    				')
	print('\n\t_________________________________________________________________________________')
	print('\t|                             Cipher Algotrithms                                 |')
	print('\t|--------------------------------------------------------------------------------|')
	print('\t|      Vector     |       AES-ECB      |       AES-CBC      |      RSA-OAEP      |')
	print('\t|--------------------------------------------------------------------------------|')
	for t in range(20):
		print('\t|      ',str(t).zfill(2),'       |      {:0.6f}      |      {:0.6f}      |      {:0.6f}      |'.format(timeAesEcb[t],timeAesCbc[t], cipherTimeRsaOaep[t]))
	print('\t|--------------------------------------------------------------------------------|')
	print('\t|    Media total  |      {:0.6f}      |      {:0.6f}      |      {:0.6f}      |'.format(avgAesEcb, avgAesCbc, cipherAvgRsaOaep))
	print('\t|--------------------------------------------------------------------------------|')
	print('\t| Total vectors analyzed: AES-ECB:',len(timeAesEcb),', AES-CBC:',len(timeAesCbc),', RSA-OAEP: ',len(cipherTimeRsaOaep),'         |')
	print('\t|________________________________________________________________________________|\n')
	print('\n\t_________________________________________________________________________________')
	print('\t|                            Decipher Algorithms                                 |')
	print('\t|--------------------------------------------------------------------------------|')
	print('\t|      Vector     |       AES-ECB      |       AES-CBC      |      RSA-OAEP      |')
	print('\t|--------------------------------------------------------------------------------|')
	for t in range(20):
		print('\t|      ',str(t).zfill(2),'       |      {:0.6f}      |      {:0.6f}      |      {:0.6f}      |'.format(dTimeAesEcb[t],dTimeAesCbc[t], decipherTimeRsaOaep[t]))
	print('\t|--------------------------------------------------------------------------------|')
	print('\t|    Media total  |      {:0.6f}      |      {:0.6f}      |      {:0.6f}      |'.format(decipherAvgAesEcb, decipherAvgAesCcb, decipherAvgRsaOaep))
	print('\t|--------------------------------------------------------------------------------|')
	print('\t| Total vectors analyzed: AES-ECB:',len(dTimeAesEcb),', AES-CBC:',len(dTimeAesCbc),', RSA-OAEP: ',len(decipherTimeRsaOaep),'         |')
	print('\t|________________________________________________________________________________|\n')
	print('\n\t______________________________________________________________________________________________________________')
	print('\t|                                               Hashing Algorithms                                            |')
	print('\t|-------------------------------------------------------------------------------------------------------------|')
	print('\t|      Vector     |        SHA384       |        SHA512       |        SHA3_384      |        SHA3_512        |')
	print('\t|-------------------------------------------------------------------------------------------------------------|')
	for t in range(20):
		print('\t|      ',str(t).zfill(2),'       |      {:0.7f}      |      {:0.7f}      |      {:0.8f}      |      {:0.8f}        |'.format(sha384time[t],sha512time[t], sha3_384time[t], sha3_512time[t]))
	print('\t|-------------------------------------------------------------------------------------------------------------|')
	print('\t|    Media total  |      {:0.7f}      |      {:0.7f}      |      {:0.7f}       |      {:0.8f}        |'.format(avgSha384, avgSha512, avgSha3_384, avgSha3_512))
	print('\t|-------------------------------------------------------------------------------------------------------------|')
	print('\t|          Total vectors analyzed: SHA384:',len(sha384time),', SHA512:',len(sha512time),', SHA3_384:',len(sha3_384time),', SHA3_512:',len(sha3_512time),'                 |')
	print('\t|_____________________________________________________________________________________________________________|\n')
	print('\n\t_________________________________________________________________________________')
	print('\t|                             Signing Algorithms                                 |')
	print('\t|--------------------------------------------------------------------------------|')
	print('\t|      Vector     |       RSA-PSS      |         DSA        |        ECDSA       |')
	print('\t|--------------------------------------------------------------------------------|')
	for t in range(7):
		print('\t|      ',str(t).zfill(2),'       |      {:0.6f}      |      {:0.6f}      |      {:0.6f}      |'.format(finalTimeRsaPss[t],finalTimeDSA[t], finalTimeECDSA[t]))
	print('\t|--------------------------------------------------------------------------------|')
	print('\t|    Media total  |      {:0.6f}      |      {:0.6f}      |      {:0.6f}      |'.format(signAvgRsaPss, signAvgDSA, signAvgECDSA))
	print('\t|--------------------------------------------------------------------------------|')
	print('\t|           Total vectors analyzed: RSA-PSS:',len(finalTimeRsaPss),', DSA:',len(finalTimeRsaPss),', ECDSA:',len(finalTimeECDSA),'              |')
	print('\t|________________________________________________________________________________|\n')
	print('\n\t_________________________________________________________________________________')
	print('\t|                           Signature Verification                               |')
	print('\t|--------------------------------------------------------------------------------|')
	print('\t|      Vector     |       RSA-PSS      |         DSA        |        ECDSA       |')
	print('\t|--------------------------------------------------------------------------------|')
	for t in range(7):
		print('\t|      ',str(t).zfill(2),'       |      {:0.6f}      |      {:0.6f}      |      {:0.6f}      |'.format(verifyingTimeRsaPss[t],verifyingTimeDSA[t], verifyingTimeECDSA[t]))
	print('\t|--------------------------------------------------------------------------------|')
	print('\t|    Media total  |      {:0.6f}      |      {:0.6f}      |      {:0.6f}      |'.format(verifyAvgRsaPss, verifyAvgDSA, verifyAvgECDSA))
	print('\t|--------------------------------------------------------------------------------|')
	print('\t|           Total vectors analyzed: RSA-PSS:',len(verifyingTimeRsaPss),', DSA:',len(verifyingTimeRsaPss),', ECDSA:',len(verifyingTimeECDSA),'              |')
	print('\t|________________________________________________________________________________|\n')
	

def main():
	global timeAesEcb, timeAesCbc, cipherTimeRsaOaep, decipherTimeRsaOaep, dTimeAesEcb, dTimeAesCbc
	global sha384time, sha512time, sha3_384time, sha3_512time
	global finalTimeRsaPss, finalTimeDSA, finalTimeECDSA, verifyingTimeRsaPss, verifyingTimeDSA, verifyingTimeECDSA
	global avgAesEcb, avgAesCbc, cipherAvgRsaOaep, decipherAvgAesEcb, decipherAvgAesCcb, decipherAvgRsaOaep
	global avgSha384, avgSha512, avgSha3_384, avgSha3_512
	global signAvgRsaPss, signAvgDSA, verifyAvgRsaPss, verifyAvgDSA, signAvgECDSA, verifyAvgECDSA
	cipherTimeRsaOaep, decipherTimeRsaOaep, finalTimeRsaPss, verifyingTimeRsaPss = [],[],[],[]

	print("Generating test vectors for AES-ECB...")
	timeAesEcb, dTimeAesEcb = AES_ECB(AesVectorInput("testVectorsAES256.txt"),0)
	avgAesEcb, decipherAvgAesEcb = averageRuntime("cryp", timeAesEcb, dTimeAesEcb)

	print("Generating test vectors for AES-CBC...")
	timeAesCbc, dTimeAesCbc = AES_CBC(AesVectorInput("testVectorsAES256.txt"),0)
	avgAesCbc, decipherAvgAesCcb = averageRuntime("cryp", timeAesCbc, dTimeAesCbc)

	print("Generating test vectors for RSA-OAEP...")
	for i in range (20):
		t1,t2 = RSA_OAEP()
		cipherTimeRsaOaep.append(t1)
		decipherTimeRsaOaep.append(t2)
	cipherAvgRsaOaep, decipherAvgRsaOaep = averageRuntime("cryp", cipherTimeRsaOaep, decipherTimeRsaOaep)

	print("Generating test vectors for SHA384...")
	sha384time = shaAlgorithms(1,"testVectorsSHA384.txt",1024)
	avgSha384 = averageRuntime("hash",sha384time,0)
	print("Generating test vectors for SHA512...")
	sha512time = shaAlgorithms(2,"testVectorsSHA512.txt",1024)
	avgSha512 = averageRuntime("hash",sha512time,0)
	print("Generating test vectors for SHA3_384...")
	sha3_384time = shaAlgorithms(3,"testVectorsSHA384.txt",1024)
	avgSha3_384 = averageRuntime("hash",sha3_384time,0)
	print("Generating test vectors for SHA3_512...")
	sha3_512time = shaAlgorithms(4, "testVectorsSHA512.txt",1024)
	avgSha3_512 = averageRuntime("hash", sha3_512time,0)

	print("Generating test vectors for RSA-PSS...")
	for i in range (7):
		t1,t2 = RSA_PSS()
		finalTimeRsaPss.append(t1)
		verifyingTimeRsaPss.append(t2)
	signAvgRsaPss, verifyAvgRsaPss = averageRuntime("cryp", finalTimeRsaPss, verifyingTimeRsaPss)

	print("Generating test vectors for DSA...")
	finalTimeDSA, verifyingTimeDSA = DSA_alg(DsaVectorInput("testVectorsDSA.txt"),0)
	signAvgDSA, verifyAvgDSA = averageRuntime("cryp", finalTimeDSA, verifyingTimeDSA)

	print("Generating test vectors for ECDSA...")
	finalTimeECDSA, verifyingTimeECDSA = ecdsa_alg("testVectorsECDSA.txt")
	signAvgECDSA, verifyAvgECDSA = averageRuntime("cryp", finalTimeECDSA, verifyingTimeECDSA)

	table()

def averageRuntime(modo,tiempo_c,tiempo_d):
	suma_c, suma_d, suma_h = 0,0,0
	if modo == "cryp":
		for i in range(len(tiempo_c)):
			suma_c += tiempo_c[i]
			suma_d += tiempo_d[i]
		mediac = suma_c/(len(tiempo_c))
		mediad = suma_d/(len(tiempo_d))
		return mediac, mediad
	elif modo == "hash":
		for i in range(len(tiempo_c)):
			suma_h += tiempo_c[i]
		media = suma_h/(len(tiempo_c))
		return media

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		exit()