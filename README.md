# nerveskey_pkcs11

This is a minimal implementation of [PKCS #11](https://en.wikipedia.org/wiki/PKCS_11)
for interacting with the NervesKey.  The NervesKey is a specific configuration
of the ATECC508A/ATECC608A chips that holds one private key in slot 0. If you're
using these chips in a similar configuration, this should work for you as well.

Another option is to look at
[cryptoauth-openssl-engine](https://github.com/MicrochipTech/cryptoauth-openssl-engine)
or [cryptoauthlib](https://github.com/MicrochipTech/cryptoauthlib).

## Building

This library is self-contained with no dependencies other that a C compiler.

```sh
make
```

## OpenSSL integration

To use this with OpenSSL, you'll need `libpkcs11.so`. This library comes from
[OpenSC's libp11](https://github.com/OpenSC/libp11) and can be installed on
Debian systems by running:

```sh
sudo apt install opensc-pkcs11
```

## Invocation from Erlang and Elixir

Erlang's `crypto` application provides an API for loading OpenSSL engines. See
[the Erlang crypto User's Guide](http://erlang.org/doc/apps/crypto/engine_load.html)
for details on this feature. I use the `dynamic` engine to load `libpkcs11.so`
which in turn loads this PKCS #11 implementation. Here's and example call in
Elixir:

```elixir
{:ok, engine} =
  :crypto.engine_load(
    "dynamic",
    [{"SO_PATH", "/usr/lib/engines-1.1/libpkcs11.so"}, {"ID", "pkcs11"}, "LOAD"],
    [{"MODULE_PATH", "nerveskey_pkcs11.so")}]
  )
```

Update the path to `libpkcs11.so` and `nerveskey_pkcs11.so` for your system.

After you load the engine, you'll eventually want to use it. The intended use
case is for delegate the ECDSA operation to the ATECC508A for use with TLS
connections. You'll need to obtain the X.509 certificate that corresponds to the
private key held in the ATECC508A through some mechanism. Then in your SSL
options, you'll have something like this:

```elixir
[
  key: %{algorithm: :ecdsa, engine: engine, key_id: "pkcs11:id=0;type=private"},
  certfile: "device-cert.pem",
]
```


