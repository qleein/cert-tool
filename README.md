# cert-tool
A GUI tool to operate X.509 certificate, based on webcrypto/webassembly.


## How To Use

1. Dependence

    * Emscripten SDK: see the [official document](https://github.com/emscripten-core/emsdk)
    * Go 1.11 or later: download [here](https://golang.org/doc/install)

2. complie openssl by Emscripten

```
$ cd /path/to/emsdk
$ source ./emsdk_env.sh
$ cd /path/to/openssl
$ emconfigure ./config no-asm no-shared no-threads no-zlib
$ emmake make
```

3. build project

clone project

```
$ git clone https://github.com/qlees/cert-tool.git
```

build cert.wasm using Go

```
$ cd cert-tool
$ GOOS=js GOARCH=wasm go build -o cert.wasm cert.go
$ cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .
```

build pfx2pem.wasm using Emscripten

```
$ cd /path/to/emsdk
$ source ./emsdk_env.sh
$ emcc -o pfx2pem.js -I /path/to/openssl/include -L/path/to/openssl/ pfx2pem.c -O3 -s WASM=1 -s "EXTRA_EXPORTED_RUNTIME_METHODS=['ccall']" -lcrypto
```

4. start a http server

If using python

Now webassembly must be loaded by fetch method, so a http server is needed; 

* add wasm to mime types: `echo "application/wasm wasm" >> /usr/local/etc/mime.types`
* start httpserver: `python -m SimpleHTTPServer` or `python3 -m http.server`.


## online demo

* Create certificate online, Click[ here ](https://tool.qlee.in/cert/create.html).
* Convert DER/PKCS12/PFX/JKS certificate to PEM format online, Click[ here ](https://tool.qlee.in/cert/convert.html).

## Q&A

### 1. compile openssl failed, error: stdatomic.h not found

this patch would resolve it

```
diff --git a/include/internal/refcount.h b/include/internal/refcount.h
index 75d70a6418..3bda6bcbec 100644
--- a/include/internal/refcount.h
+++ b/include/internal/refcount.h
@@ -17,7 +17,7 @@
 # endif
 
 # if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L \
-     && !defined(__STDC_NO_ATOMICS__)
+     && !defined(__STDC_NO_ATOMICS__) && !defined(__EMSCRIPTEN__)
 #  include <stdatomic.h>
 #  define HAVE_C11_ATOMICS
 # endif
diff --git a/include/internal/tsan_assist.h b/include/internal/tsan_assist.h
index f30ffe398a..cc72f9b3a2 100644
--- a/include/internal/tsan_assist.h
+++ b/include/internal/tsan_assist.h
@@ -48,7 +48,7 @@
  */
 
 #if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L \
-    && !defined(__STDC_NO_ATOMICS__)
+    && !defined(__STDC_NO_ATOMICS__) && !defined(__EMSCRIPTEN__)
 # include <stdatomic.h>
 
 # if defined(ATOMIC_POINTER_LOCK_FREE) \
```

### 2. compile openssl failed, error: /path/to/emcc not found

check the emcc path `which emcc`, maybe you should modify the variable $CROSS_COMPILE in Makefile, make sure the $CC and $CXX path is correct.

### 3. Uncaught (in promise) TypeError: Failed to execute 'compile' on 'WebAssembly': Incorrect response MIME type. Expected 'application/wasm'

you should add `application/wasm` to httpserver's mine.types

* if using python, `echo "application/wasm wasm >> /usr/local/etc/mime.types`
* if using Nginx, add `application/wasm wasm` to /path/to/nginx/conf/mime.types
