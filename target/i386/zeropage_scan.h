/*
 * Zero page scanner
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_ZEROPAGE_SCAN_H
#define QEMU_ZEROPAGE_SCAN_H

void zeropage_scan_init(void);
void zeropage_scan_enable(MemoryRegion *mr, uint64_t timeout_ms);

#endif
