# QEMU virtio device fuzzing with AFL

Describe how to configure and prepare QEMU for fuzzing with AFL. The source code for both QEMU and AFL can be found at
* QEMU changes (afl-fuzz branch): https://github.com/yandex/qemu/tree/afl-fuzz
* AFL changes (qemu-fuzz branch):  https://github.com/yandex/AFL/tree/qemu-fuzz

## Prepare AFL binary

To get the best from AFL (instrumentation, persistent mode and so on) it is good to compile the afl-clang-fast wrapper. Checkout AFL and build it (check AFL's README file). The easy way to compile AFL is:
~~~
$ cd <afl_root>
$ make
$ cd <afl_root>/llvm_mode
$ make
~~~
After these commands the afl-fuzz and afl-clang-fast applications should exist in the afl_root path.

## Prepare QEMU binary

Run configure with the required options to prepare QEMU for building:
~~~
./configure ...
~~~

Build QEMU with AFL instrumentation. Note that it is not recommended to instrument all the QEMU source code. Instrument only part of the QEMU. It can be done using the environment variables:
~~~
$ AFL_PATH=<afl_root> AFL_MODS="hw/block hw/virtio" make
~~~
AFL_PATH is required to locate the afl-clang-fast binary. AFL_MODS environment variable defines the modules in QEMU which should be instrumented.
Note: afl-clang-fast is using clang to compile QEMU. Sometimes this requires to update QEMU sources.

Prepare the proxy application (located in the QEMU repo):
~~~
$ make tests/test_proxy
~~~

Check the binaries: qemu-system-x86_64, afl-fuzz and test_proxy. Now QEMU is ready for the virtio block device fuzzing.

## Start the fuzzing process

As a demonstration the following command could be use to start QEMU:
~~~
qemu-system-x86_64 -qtest unix:/tmp/qtest.sock,nowait -machine accel=qtest -display none -nodefaults -drive if=none,id=drive0,file=<rawblockdevice>,format=raw -device virtio-blk-pci,id=v0,drive=drive0,addr=4.0 -qtest-log /dev/null
~~~

Let's prepare a small file to use it as a block device:
~~~
fallocate -l 64M blocktest.raw
~~~

The QEMU command will be:
~~~
qemu-system-x86_64 -qtest unix:/tmp/qtest.sock,nowait -machine accel=qtest -display none -nodefaults -drive if=none,id=drive0,file=blocktest.raw,format=raw -device virtio-blk-pci,id=v0,drive=drive0,addr=4.0 -qtest-log /dev/null
~~~

Run the proxy application to redirect the input from AFL to QEMU (both of them are using unix socket communication):
~~~
$ test_proxy -a /tmp/afl.sock -q /tmp/qtest.sock
~~~

Run the fuzzing process, for out simple demonstration it can be run as:
~~~
$ afl-fuzz -m none -t 5000 -u /tmp/afl.sock -i <qemu_root>/tests/virtio_blk_testcases_in -o <output_dir> -- <qemu_root>/x86_64-softmmu/qemu-system-x86_64 -qtest unix:/tmp/qtest.sock,nowait -machine accel=qtest -display none -nodefaults -drive if=none,id=drive0,file=blocktest.raw,format=raw -device virtio-blk-pci,id=v0,drive=drive0,addr=4.0 -qtest-log /dev/null
~~~

Note: virtio_blk_testcases_in directory contains start input files. Each file is just a virtio descriptor table with block request. The <output_dir> directory should be defined to store crashes and issues.
