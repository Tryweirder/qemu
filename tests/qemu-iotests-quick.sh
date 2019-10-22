#!/bin/sh

cd tests/qemu-iotests

ret=0
TEST_DIR=${TEST_DIR:-/tmp/qemu-iotests-quick-$$} ./check -T -raw -g quick || ret=1

exit $ret
