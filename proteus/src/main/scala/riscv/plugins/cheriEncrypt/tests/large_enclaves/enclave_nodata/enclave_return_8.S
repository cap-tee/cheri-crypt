#2inst. = 8 bytes
1:
enclave_return:
	# 3. return from enclave
	 #clear data capability tag from register and return from enclave
	 CClearTag c31, c31
	 CJALR cra


