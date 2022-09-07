# FeIDo Middleware Android App
This is the Android prototype of the FeIDo client middleware.
The middleware acts an intermediate between the eID, Credential Service, and
browser extension.

## Build Preparation
1. Initialize the submodule(s):
    ```
    git submodule update --init --recursive
    ```


2. Patch the ra-tls library:
    ```
    cd external/java-ra-tls-client
    patch -p1 < ../../patches/patch_to_9ccbbd212a19125f77f8c8742df1926cff4a58d2_java-ra-tls-client.patch
    ```


3. Manually configure the IP Addresses of the Credential Service and optionally
    adapt the port on which the middleware's websocket server should be listening
    for connections by the browser extension:

    In the `LinearFEIDO.java` source file, adapt the `SGXIP` (and optionally, `SGXPort`)
    fields to configure the address of the Credential Service to which the middleware
    will connect.

    Optionally, adapt the middleware's websocket server port by changing the `webSocketServerPort`
    field in the same source file.



## Build Instructions
Open the folder in a recent version of Android Studio and build + install the app
on an Android phone *with NFC support*.

We have successfully tested the prototype using a `Samsung Galaxy S8` with `Android 9 (Pie)`
installed.


## Limitations
Note that the current version of the FeIDo middleware app is a proof of concept, not a production-ready prototype.
The current implementation does not perform thorough cleanup and exception handling and might face callstack-related overflows.
