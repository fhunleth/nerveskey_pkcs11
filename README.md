# nerveskey_pkcs11


## Installation

```sh
sudo apt install opensc-pkcs11
```

## Things I don't understand yet

How does p11-kit fit in without of this?

```sh
$ p11-kit list-modules             master*
p11-kit-trust: p11-kit-trust.so
    library-description: PKCS#11 Kit Trust Module
    library-manufacturer: PKCS#11 Kit
    library-version: 0.23
    token: System Trust
        manufacturer: PKCS#11 Kit
        model: p11-kit-trust
        serial-number: 1
        hardware-version: 0.23
        flags:
               write-protected
               token-initialized
opensc-pkcs11: opensc-pkcs11.so
    library-description: OpenSC smartcard framework
    library-manufacturer: OpenSC Project
    library-version: 0.17
```

## Links

* https://raymii.org/s/articles/Get_Started_With_The_Nitrokey_HSM.html#PKCS#11,_#15_and_OpenSC
* https://github.com/CardContact/sc-hsm-embedded
* https://p11-glue.github.io/p11-glue/
