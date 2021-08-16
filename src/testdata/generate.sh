#!/bin/bash -e

openssl genpkey \
	--algorithm=rsa \
	--pkeyopt=rsa_keygen_bits:2048 |\
	openssl pkey \
	--pubout \
	--outform=der > rsa_pub.der
