# Key pair generation with OpenSSL

## generate key pair

````
openssl genrsa -des3 -out private.pem 2048
````

## Extract public key

````
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
````

## Convert PEM to DER

````
openssl rsa -pubin -inform PEM -in public.pem -outform DER -out public.der
````
