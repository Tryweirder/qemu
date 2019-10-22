/*
 * QTest testcase for VirtIO RNG
 *
 * Copyright (c) 2014 SUSE LINUX Products GmbH
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/pci.h"

#define PCI_SLOT_HP             0x06

/* Tests only initialization so far. TODO: Replace with functional tests */
static void pci_nop(void)
{
}

static void hotplug(void)
{
    const char *arch = qtest_get_arch();
    const char *mtype = qtest_get_default_machine_type();

    g_assert(mtype);
    bool is_q35 = (strcmp(mtype, "q35") == 0);

    if (is_q35) {
        qtest_start("-device virtio-rng-pci "\
            "-device ioh3420,multifunction=on,port=1,chassis=1,id=ioh.1 ");
        qpci_plug_device_test("virtio-rng-pci", "rng1", PCI_SLOT_HP,
                              "'bus':'ioh.1'");
    } else {
        qtest_start("-device virtio-rng-pci");
        qpci_plug_device_test("virtio-rng-pci", "rng1", PCI_SLOT_HP, NULL);
    }

    if (strcmp(arch, "i386") == 0 || strcmp(arch, "x86_64") == 0) {
        qpci_unplug_acpi_device_test("rng1", PCI_SLOT_HP);
    }

    qtest_end();
    g_free((void *)mtype);
}

int main(int argc, char **argv)
{
    int ret;

    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/virtio/rng/pci/nop", pci_nop);
    qtest_add_func("/virtio/rng/pci/hotplug", hotplug);

    ret = g_test_run();

    return ret;
}
