/*

1. We will introduce Admin enclaves
2. The operator that wants to upgrade enclave binary will:
	2-1. Construct payload with its own enclave account key
	2-2. Sign the payload with operator private key
	2-3. Send the signed message to Admin TEE enclave.
	2-4. Admin TEE enclave will expose an API to receive this message.
3. The operator will install and start the new enclave binary
4. The new enclave binary will request admin TEE for the key backup. Need an UI where operator can trigger this.
5. The Admin TEE will do remote attestation of the enclave . If succeeds, it will return the payload signed with the public key of the operator.
6. The enclave will replace the existing account key , with the backup received from Admin TEE.

 */
