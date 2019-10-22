/*
 * VFIO region filters
 *
 * Copyright Yandex N.V. 2019
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifndef HW_VFIO_REGION_FILTER_H
#define HW_VFIO_REGION_FILTER_H

#include "qom/object.h"
#include "qemu/queue.h"

typedef struct VFIOPCIDevice VFIOPCIDevice;

typedef struct VFIORegionFilter {
    Object parent_obj;
    int region_num;

    /*
     * List of PCI vendor/device ids this filter should match against
     */
    uint32_t *pci_ids;
    size_t total_ids;

    /*
     * LE32-encoded filter masks
     *
     * An intercepted write to a location that has all bits set to 1
     * should be passed through directly.
     *
     * An intercepted write to a location that has all bits set to 0
     * should be dropped.
     *
     * An intercepted write smaller than 4-bytes or a write that's not naturally
     * aligned, to a location that only has some bits set to 1 should
     * be dropped.
     *
     * An intercepted 4-byte, or larger, naturally aligned write to a location
     * that only has some bits set to 1 needs to be handled by first
     * reading the location from the device with a read access of the same size.
     * The read value should have all the bits that are writable set to zero,
     * and then reset to the values from the intercepted write. Finally the
     * merged result needs to be written back to the device.
     */
    uint8_t *data;
    size_t size;

    /*
     * Total number of writes we either dropped or partially filtered.
     * Accessible through QMP as a QOM object property, for statistics
     */
    uint64_t writes_dropped;
    uint64_t writes_filtered;

    bool completed; /* All object properties were set */
    QLIST_ENTRY(VFIORegionFilter) link;
} VFIORegionFilter;

#define TYPE_VFIO_REGION_FILTER "vfio-pci-region-filter"
#define VFIO_REGION_FILTER(obj) \
   OBJECT_CHECK(VFIORegionFilter, obj, TYPE_VFIO_REGION_FILTER)

/**
 * Lookup region filter by PCI id, region number and region size.
 * Caller is responsible to object_unref returned QOM object when it is done using it.
 */
VFIORegionFilter *vfio_lookup_region_filter(const VFIOPCIDevice *vdev,
                                            int region_num,
                                            size_t size);

/**
 * Unref filter object previously aquired by vfio_lookup_region_filter.
 */
void vfio_put_region_filter(VFIORegionFilter *filter);

#endif
