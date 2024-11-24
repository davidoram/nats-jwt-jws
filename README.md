
# NATS JSON Web Signature (JWS) from NATS credentials

Show how to a NATS user can create a JWS from a standard NATS credentials file, which is signed by the user with their private key, then on the server side how that JWS can be decoded and verified as having being signed by using the Users public key (ie: `sub` field in JWT)

The resulting JWT could be used for example as a NATS Header that could be sent alongside messages, so that the server side could use the header to store audit information about who sent the message.

To run `go run main.go /path/to/nats.creds`