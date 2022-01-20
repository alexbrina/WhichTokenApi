## ECDsa signed tokens

If using ECDsa signed tokens, you may want to create you own asymmetric keys and certificate

```bash
# generate a private key for a curve
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem

# generate corresponding public key
openssl ec -in private-key.pem -pubout -out public-key.pem

# create a self-signed certificate
openssl req -new -x509 -key private-key.pem -out certificate.pem -days 365

# convert pem to pfx (you'll be asked for a secret to protect you certificate)
openssl pkcs12 -export -inkey private-key.pem -in certificate.pem -out certificate.pfx

# PS: If on Windows, you may find openssl in your git installation under <path-to>\Git\usr\bin
```