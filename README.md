![SHREQ](https://cyberphone.github.io/doc/security/shreq.svg)

# Signed HTTP Requests (SHREQ)

Java code for SHREQ demo and validation

### Testing with "Curl"
This line POSTs a signed JSON request:
```code
$ curl -k -d @rs512@imp.json -i -H "Content-Type:application/json" https://localhost:8442/shreq/preconfreq?something=7
```
Note: the -k option is *only for testing* using self-certified servers!
