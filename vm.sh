#!/bin/bash -xe

exec vng --disable-microvm --verbose --cpus 4 --console --qemu-opts="-chardev socket,id=chrtpm,path=/home/ignat/tpm/swtpm-sock" --qemu-opts="-tpmdev emulator,id=tpm0,chardev=chrtpm" --qemu-opts="-device tpm-tis,tpmdev=tpm0"
