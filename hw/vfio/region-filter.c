/*
 * VFIO region filters
 *
 * Copyright Yandex N.V. 2019
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/bswap.h"
#include "qemu/cutils.h"
#include "hw/vfio/region-filter.h"
#include "hw/vfio/pci.h"
#include "qom/object.h"
#include "qom/object_interfaces.h"
#include "qapi/error.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qobject.h"
#include "qapi/qmp/qstring.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qlist.h"

static QemuMutex g_region_filters_lock;
static QLIST_HEAD(, VFIORegionFilter) g_region_filters;

#define VFIO_REGION_FILTER_MAX_SIZE     (16ull * 1024 * 1024) /* 16 MB so far */
#define VFIO_REGION_FILTER_MAX_PCI_IDS  (256)

static bool match_pci_id(const VFIOPCIDevice *vdev, const VFIORegionFilter *filter)
{
    uint32_t pci_id = (vdev->vendor_id << 16) | vdev->device_id;

    for (size_t i = 0; i < filter->total_ids; ++i) {
        if (filter->pci_ids[i] == pci_id) {
            return true;
        }
    }

    return false;
}

VFIORegionFilter *vfio_lookup_region_filter(const VFIOPCIDevice *vdev,
                                            int region_num,
                                            size_t size)
{
    if (!vdev) {
        return NULL;
    }

    qemu_mutex_lock(&g_region_filters_lock);

    VFIORegionFilter *filter;
    QLIST_FOREACH(filter, &g_region_filters, link) {
        if (filter->region_num != region_num) {
            continue;
        }

        if (filter->size != size) {
            continue;
        }

        if (!match_pci_id(vdev, filter)) {
            continue;
        }

        object_ref(OBJECT(filter));
        qemu_mutex_unlock(&g_region_filters_lock);
        return filter;
    }

    qemu_mutex_unlock(&g_region_filters_lock);
    return NULL;
}

void vfio_put_region_filter(VFIORegionFilter *filter)
{
    if (filter) {
        object_unref(OBJECT(filter));
    }
}

static uint64_t qstring_to_u64(QString *str, Error **errp)
{
    uint64_t val;
    if (0 != qemu_strtou64(qstring_get_str(str), NULL, 0, &val)) {
        error_setg(errp, "malformed number string %s", qstring_get_str(str));
        return -1;
    }

    return val;
}

static uint64_t qdict_get_u64(QDict *dict, const char *key, Error **errp)
{
    QString *str = qobject_to(QString, qdict_get(dict, key));
    if (!str) {
        error_setg(errp, "missing region mask key");
        return -1;
    }

    return qstring_to_u64(str, errp);
}

static void vfio_region_filter_set_filter(Object *obj, const char *str, Error **errp)
{
    VFIORegionFilter *filter = VFIO_REGION_FILTER(obj);
    Error *local_err = NULL;

    /* Clear old data in case filter property is reset */
    g_free(filter->pci_ids);
    g_free(filter->data);
    filter->total_ids = 0;
    filter->size = 0;

    int fd = qemu_open(str, O_RDONLY);
    if (fd < 0) {
        error_setg_errno(errp, errno, "failed to open filter definition file");
        return;
    }

    off_t fsize = lseek(fd, 0, SEEK_END);
    if (fsize < 0) {
        error_setg_errno(errp, errno, "lseek failed");
        goto close_file;
    }

    void *json_data = mmap(NULL, fsize, PROT_READ, MAP_SHARED, fd, 0);
    if (json_data == MAP_FAILED) {
        error_setg_errno(errp, errno, "failed to mmap filter file");
        goto close_file;
    }

    QObject *json_obj = qobject_from_json(json_data, errp);
    if (!json_obj) {
        goto unmap_file;
    }

    QDict *dict = qobject_to(QDict, json_obj);
    if (!dict) {
        error_setg(errp, "Can't get dictionary for the region filter");
        goto decref;
    }

    QList *ranges = qobject_to(QList, qdict_get(dict, "ranges"));
    if (!ranges) {
        error_setg(errp, "Can't get ranges list");
        goto decref;
    }

    QList *ids = qobject_to(QList, qdict_get(dict, "pci_vendor_device_ids"));
    if (!ids || qlist_empty(ids)) {
        error_setg(errp, "Can't get PCI id list, or list is empty");
        goto decref;
    }

    size_t total_ids = qlist_size(ids);
    if (total_ids > VFIO_REGION_FILTER_MAX_PCI_IDS) {
        error_setg(errp, "PCI ids list too large: %zu", total_ids);
        goto decref;
    }

    uint64_t region_size = qdict_get_u64(dict, "size", &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        goto decref;
    } else if (region_size == 0 || region_size > VFIO_REGION_FILTER_MAX_SIZE) {
        error_setg(errp, "Bad region size 0x%" PRIx64, region_size);
        goto decref;
    }

    /* Construct filter from json data */
    uint32_t *pci_ids = g_malloc(sizeof(*pci_ids) * total_ids);
    uint8_t *data = g_malloc0(region_size); /* Fill possible range gaps with 0-es */

    QString *pci_id;
    uint32_t *pci_ids_ptr = pci_ids;
    while ((pci_id = qobject_to(QString, qlist_pop(ids))) != NULL) {
        uint64_t val = qstring_to_u64(pci_id, &local_err);
        QDECREF(pci_id);

        if (local_err != NULL) {
            error_propagate(errp, local_err);
            goto free_data;
        }

        if (val > UINT32_MAX) {
            error_setg(errp, "PCI id 0x%" PRIx64 " should be 32 bits long", val);
            goto free_data;
        }

        *pci_ids_ptr++ = (uint32_t) val;
    }

    QDict *range;
    while ((range = qobject_to(QDict, qlist_pop(ranges))) != NULL) {
        uint64_t mask = qdict_get_u64(range, "mask", &local_err);
        if (local_err != NULL) {
            QDECREF(range);
            error_propagate(errp, local_err);
            goto free_data;
        }

        uint64_t offset = qdict_get_u64(range, "offset", &local_err);
        if (local_err != NULL) {
            QDECREF(range);
            error_propagate(errp, local_err);
            goto free_data;
        }

        uint64_t size = qdict_get_u64(range, "size", &local_err);
        if (local_err != NULL) {
            QDECREF(range);
            error_propagate(errp, local_err);
            goto free_data;
        }

        QDECREF(range);

        /* Masks should be 4-byte values */
        if (mask > UINT32_MAX) {
            error_setg(errp, "range mask %#" PRIx64 " does not fit into 4 bytes", mask);
            goto free_data;
        }

        /* Offset should be 4-byte aligned */
        if (offset & 0x3) {
            error_setg(errp, "range offset %#" PRIx64 " must be 4-byte aligned", offset);
            goto free_data;
        }

        /* Size should be 4-byte aligned */
        if (size & 0x3) {
            error_setg(errp, "range size %#" PRIx64 " must be 4-byte aligned", size);
            goto free_data;
        }

        if (offset >= region_size) {
            error_setg(errp, "range offset %#" PRIx64 " out of bounds", offset);
            goto free_data;
        }

        if (size == 0 || size > region_size - offset) {
            error_setg(errp, "range size %#" PRIx64 " is invalid or out of bounds", size);
            goto free_data;
        }

        /* Masks are stored in LE32 (4-byte little endian), convert if needed */
        uint32_t mask32 = cpu_to_le32((uint32_t)mask);
        uint32_t* pdata32 = (uint32_t *)(data + offset);
        for (size_t i = 0; i < size / sizeof(uint32_t); ++i) {
            pdata32[i] = mask32;
        }
    }

    filter->pci_ids = pci_ids;
    filter->total_ids = total_ids;
    filter->data = data;
    filter->size = region_size;

    goto decref;

free_data:
    g_free(pci_ids);
    g_free(data);

decref:
    qobject_decref(json_obj);

unmap_file:
    munmap(json_data, fsize);

close_file:
    qemu_close(fd);
}

static void vfio_region_filter_get_region_num(Object *obj, Visitor *v,
                                              const char *name, void *opaque,
                                              Error **errp)
{
    VFIORegionFilter *filter = VFIO_REGION_FILTER(obj);

    int64_t value = filter->region_num;
    visit_type_int(v, name, &value, errp);
}

static void vfio_region_filter_set_region_num(Object *obj, Visitor *v,
                                              const char *name, void *opaque,
                                              Error **errp)
{
    VFIORegionFilter *filter = VFIO_REGION_FILTER(obj);

    int64_t value;
    visit_type_int(v, name, &value, errp);
    filter->region_num = value;
}

static void vfio_region_filter_get_writes_dropped(Object *obj, Visitor *v,
                                                  const char *name, void *opaque,
                                                  Error **errp)
{
    VFIORegionFilter *filter = VFIO_REGION_FILTER(obj);

    uint64_t value = filter->writes_dropped;
    visit_type_uint64(v, name, &value, errp);
}

static void vfio_region_filter_get_writes_filtered(Object *obj, Visitor *v,
                                                   const char *name, void *opaque,
                                                   Error **errp)
{
    VFIORegionFilter *filter = VFIO_REGION_FILTER(obj);

    uint64_t value = filter->writes_filtered;
    visit_type_uint64(v, name, &value, errp);
}

/* Called after object properties are set */
static void vfio_region_filter_complete(UserCreatable *obj, Error **errp)
{
    VFIORegionFilter *filter = VFIO_REGION_FILTER(obj);

    if (!filter->data) {
        error_setg(errp, "filter_path property was not set");
        return;
    }

    qemu_mutex_lock(&g_region_filters_lock);
    QLIST_INSERT_HEAD(&g_region_filters, filter, link);
    qemu_mutex_unlock(&g_region_filters_lock);

    filter->completed = true;
}

static void vfio_region_filter_finalize(Object *obj)
{
    VFIORegionFilter *filter = VFIO_REGION_FILTER(obj);

    /*
     * Finalize may be called on error path before complete was called.
     * Remove from the list only if we're in it (QLIST_REMOVE is not safe in this regard)
     */
    if (filter->completed) {
        qemu_mutex_lock(&g_region_filters_lock);
        QLIST_REMOVE(filter, link);
        qemu_mutex_unlock(&g_region_filters_lock);
    }

    g_free(filter->pci_ids);
    g_free(filter->data);
}

static void vfio_region_filter_class_init(ObjectClass *klass, void *data)
{
    UserCreatableClass *ucc = USER_CREATABLE_CLASS(klass);
    ucc->complete = vfio_region_filter_complete;

    object_class_property_add_str(klass, "filter_path",
                                  NULL,
                                  vfio_region_filter_set_filter,
                                  &error_abort);

    object_class_property_add(klass, "bar", "int",
                              vfio_region_filter_get_region_num,
                              vfio_region_filter_set_region_num,
                              NULL, NULL, &error_abort);

    object_class_property_add(klass, "writes_dropped", "uint64",
                              vfio_region_filter_get_writes_dropped,
                              NULL,
                              NULL, NULL, &error_abort);

    object_class_property_add(klass, "writes_filtered", "uint64",
                              vfio_region_filter_get_writes_filtered,
                              NULL,
                              NULL, NULL, &error_abort);

    QLIST_INIT(&g_region_filters);
    qemu_mutex_init(&g_region_filters_lock);
}

static const TypeInfo vfio_region_filter_info = {
    .name = TYPE_VFIO_REGION_FILTER,
    .parent = TYPE_OBJECT,
    .class_init = vfio_region_filter_class_init,
    .instance_size = sizeof(VFIORegionFilter),
    .instance_finalize = vfio_region_filter_finalize,
    .interfaces = (InterfaceInfo[]) {
        {TYPE_USER_CREATABLE},
        {}
    },
};

static void register_vfio_region_filter_type(void)
{
    type_register_static(&vfio_region_filter_info);
}

type_init(register_vfio_region_filter_type)
