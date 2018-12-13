
LDFLAGS += -shared -Wl,-Bsymbolic

#LDFLAGS = -shared -Wl,-Bsymbolic -Wl,-R/usr/lib -Wl,-R/usr/local/lib64 -Wl,-R/usr/sfw/lib64 -Wl,-R/usr/lib64 -Wl,-R/opt/local/lib64 -Wl,-R/usr/pkg/lib64 -Wl,-R/usr/local/openssl/lib64 -Wl,-R/usr/lib/openssl/lib64 -Wl,-R/usr/openssl/lib64 -Wl,-R/usr/local/ssl/lib64 -Wl,-R/usr/lib/ssl/lib64 -Wl,-R/usr/ssl/lib64 -Wl,-R//lib64 -Wl,-R/usr/local/lib -Wl,-R/usr/sfw/lib -Wl,-R/opt/local/lib -Wl,-R/usr/pkg/lib -Wl,-R/usr/local/openssl/lib -Wl,-R/usr/lib/openssl/lib -Wl,-R/usr/openssl/lib -Wl,-R/usr/local/ssl/lib -Wl,-R/usr/lib/ssl/lib -Wl,-R/usr/ssl/lib -Wl,-R//lib -L/usr/lib -lcrypto

#-Wl,-whole-archive -lwrapper -Wl,-no-whole-archive
CFLAGS = -Werror=undef -Werror=implicit -Werror=return-type  -Wall -Wstrict-prototypes -Wmissing-prototypes -DUSE_THREADS \
	 -D_THREAD_SAFE -D_REENTRANT -DPOSIX_THREADS -D_POSIX_THREAD_SAFE_FUNCTIONS -O2 -fno-tree-copyrename -D_GNU_SOURCE -fPIC

all: nerveskey_pkcs11.so

SRC=$(wildcard *.c)
HEADERS=$(wildcard *.h)
OBJ=$(SRC:.c=.o)

$(OBJ): $(HEADERS)

nerveskey_pkcs11.so: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) *.so *.o

format:
	astyle -n $(SRC)

.PHONY: all clean format
