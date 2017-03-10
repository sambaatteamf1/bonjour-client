# bonjour-client
mDNS browse using c-ares

## Dependencies

 - gcc and g++, gdb, gmake, valgrind
 - git
 - cmake (`apt-get install cmake`)
 - autoconf

## Build steps

1. Update submodules: 
   
   ```
   $ git submodule update --init --recursive
   ```

2. Build the main c-ares library as below

   ```
   $ cd c-ares
   $ ./configure --disable-symbol-hiding
   ```
3. Make in the root directory

   ```
   $ cmake .
   $ make 
   ```
   The binaries are built in bin/ directory
