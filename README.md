![SHREQ](https://cyberphone.github.io/doc/security/shreq.svg)

# Signed HTTP Requests

[SHREQ documentation](https://github.com/cyberphone/ietf-signed-http-requests)

This repository contains Java code for SHREQ demo and validation.

### Online Testing
There is currently a hosted version of this code at https://mobilepki.org/shreq.

### Testing with "Curl"
This line POSTs a signed JSON request:
```code
$ curl -k --data-binary @myrequest.json -i -H content-type:application/json https://localhost:8442/shreq/preconfreq?something=7
```
Note: the -k option is *only for testing* using self-certified servers!
