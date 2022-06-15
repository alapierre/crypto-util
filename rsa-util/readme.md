# Generate your own CA 

## with no key encryption

````shell
openssl req -x509 \
-sha256 -days 9125 \
-nodes \
-newkey rsa:2048 \
-subj "/CN=My test root CA/C=FR/L=St. Tropez/O=My corp" \
-keyout Digital_Signature_CA_PK.pem -out Digital_Signature_CA.crt 
````
