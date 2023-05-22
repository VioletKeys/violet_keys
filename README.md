# Violet Keys: Code

Provides an out-of-process encryption/decryption service
for server-side installed applications.

## Use-case

This project should be used with services that need to 
encrypt/decrypt data outside of the service itself. It
reduces the blast-radius of a compromise of the service,
and gives a plugable mechanism to add in encryption
schemes and key management backend.

Violet Keys runs in a separate process. Services interact
with Violet Keys through a local socket. Services will send
encryption/decryption requests to Violet Keys including 
identifiers for the material that needs cryptographic
support. Violet Keys will proxy the request to the backend
and if approved, the backend will send the keys to Violet
Keys to perform the operation... returning the results or
error to the service.
