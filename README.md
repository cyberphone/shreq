![SHREQ](https://cyberphone.github.io/doc/security/shreq.svg)

# Signed HTTP Requests

[SHREQ documentation](https://cyberphone.github.io/ietf-signed-http-requests)

This repository contains Java code for SHREQ demo and validation.

### Testing with "Curl"
This line POSTs a signed JSON request:
```code
$ curl -k -d @myrequest.json -i -H "Content-Type:application/json" https://localhost:8442/shreq/preconfreq?something=7
```
Note: the -k option is *only for testing* using self-certified servers!
