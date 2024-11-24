
Use JWT with JWS

In essesece - JWT is encrypted with a separate public key & placed in header, server decodes & verifies, then uses JWT details for audit

Tools; 

- [nk](go install github.com/nats-io/nkeys/nk@latest)

Idea 1: Generate new keypair just for the authenticating
Idea 2: Use existing keypair, maybe from the issuer (Account)

On creation of a new user we generate a unique keypair

Idea1: `nk -gen user -pubout > server.keys`

First line is 
```
SUAO2RDGNQ5N4Z5CVHGDGA53453L2ZVYE5W3M6A4WTWRLYYKYAUGUMRTYQ
UCSG37DGBCUG7M3WPU46TKLPH4RKMP62QWKIXH6NXRR7MJ6MOWZOMSJU
```

First line is Seed (Private key), second line is User (Public key)

