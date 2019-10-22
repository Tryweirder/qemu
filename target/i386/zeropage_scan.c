/*
 * Zero page scanner
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/bitmap.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "exec/memory.h"
#include "exec/cpu-common.h"
#include "kvm_i386.h"
#include "migration/misc.h"
#include "migration/vmstate.h"
#include "migration/qemu-file.h"
#include "qapi/qapi-commands-yc.h"

#include "zeropage_scan.h"

#define MIN_MEMORY_USAGE_PERCENT  90
#define MIN_DISCARD_SIZE          (10 * 1024 * 1024)
#define TIMER_INTERVAL_MS         1000

/* Use virtual clock to trigger timer only when VM is running */
static const QEMUClockType clock_type = QEMU_CLOCK_VIRTUAL;

typedef struct ZeropageScanState {
    MemoryRegion *mr;
    void *mem_addr;
    size_t mem_size;
    size_t pages_count;
    unsigned long *zeroed_bitmap;

    size_t page_size;
    size_t page_shift;
    Notifier exit_notifier;
    QEMUTimer timer;
    int64_t last_reset_time;
    int64_t discarded_size;
    bool bh_scheduled;
    uint64_t timeout_ms;
} ZeropageScanState;

static ZeropageScanState zeropage_scan_state;

static MemoryRegion *get_supported_region(MemoryRegion *mr);
static void exit_notifier_cb(Notifier *notifier, void *data);
static void reset_handler(void *opaque);
static void discard_bh_callback(void *opaque);
static void timer_callback(void *opaque);

static int zeropage_scan_timer_get(QEMUFile *f, void *pv, size_t size,
                                   VMStateField *field)
{
    QEMUTimer *ts = pv;
    uint64_t expire_time = qemu_get_be64(f);
    if (expire_time != (uint64_t)-1) {
        timer_mod_ns(ts, expire_time);
    } else {
        timer_del(ts);
    }
    return 0;
}

static int zeropage_scan_timer_put(QEMUFile *f, void *pv, size_t size,
                                   VMStateField *field, QJSON *vmdesc)
{
    QEMUTimer *ts = pv;
    uint64_t expire_time = timer_expire_time_ns(ts);
    qemu_put_be64(f, expire_time);
    return 0;
}

static const struct VMStateInfo zeropage_scan_info_timer = {
    .name = "zeropage_scan_timer",
    .get = zeropage_scan_timer_get,
    .put = zeropage_scan_timer_put,
};

static int zeropage_scan_post_load(void *opaque, int version_id)
{
    ZeropageScanState *zss = opaque;
    /* There is a chance that bh was scheduled but not called, because it was
     * interrupted by outgoing migration. Reschedule it again */
    if (zss->bh_scheduled) {
        aio_bh_schedule_oneshot(qemu_get_aio_context(), discard_bh_callback,
                                zss);
    }
    return 0;
}

static const VMStateDescription vmstate_zeropage_scan = {
    .name = "zeropage_scan_state",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = zeropage_scan_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_INT64(last_reset_time, ZeropageScanState),
        VMSTATE_INT64(discarded_size, ZeropageScanState),
        VMSTATE_SINGLE(timer, ZeropageScanState, 0,
                       zeropage_scan_info_timer, QEMUTimer),
        VMSTATE_BOOL(bh_scheduled, ZeropageScanState),
        VMSTATE_END_OF_LIST()
    },
};

static inline bool zeropage_scan_enabled(ZeropageScanState *zss)
{
    return zss->mr;
}

void zeropage_scan_init(void)
{
    ZeropageScanState *zss = &zeropage_scan_state;
    zss->page_size = getpagesize();
    assert(is_power_of_2(zss->page_size));
    zss->page_shift = ctz64(zss->page_size);
    zss->last_reset_time = -1;
    zss->discarded_size = -1;
    zss->bh_scheduled = false;
    timer_init_ms(&zss->timer, clock_type, timer_callback, zss);
    vmstate_register(NULL, 0, &vmstate_zeropage_scan, &zeropage_scan_state);
}

void zeropage_scan_enable(MemoryRegion *mr, uint64_t timeout_ms)
{
    ZeropageScanState *zss = &zeropage_scan_state;
    assert(mr);
    assert(!zeropage_scan_enabled(zss));

    /* This feature is useful mainly for Windows guests, so try to detect
     * this case by checking HyperV flags. */
    if (!kvm_enabled() || !kvm_hyperv_enabled(X86_CPU(first_cpu))) {
        return;
    }

    mr = get_supported_region(mr);
    if (!mr) {
        error_report("zeropage_scan: specified memory region is not supported");
        return;
    }

    memory_region_ref(mr);
    zss->mr = mr;
    zss->mem_addr = memory_region_get_ram_ptr(mr);
    zss->mem_size = memory_region_size(mr);
    zss->pages_count = zss->mem_size >> zss->page_shift;
    zss->zeroed_bitmap = bitmap_new(zss->pages_count);
    zss->last_reset_time = -1;
    zss->discarded_size = -1;
    zss->timeout_ms = timeout_ms;

    zss->exit_notifier.notify = exit_notifier_cb;

    qemu_register_reset(reset_handler, zss);
    qemu_add_exit_notifier(&zss->exit_notifier);
}

static void zeropage_scan_cleanup(ZeropageScanState *zss)
{
    assert(zss);
    /* It's ok to unregister non-registered handler */
    qemu_unregister_reset(reset_handler, zss);
    qemu_remove_exit_notifier(&zss->exit_notifier);
    timer_del(&zss->timer);
    memory_region_unref(zss->mr);
    g_free(zss->zeroed_bitmap);
}

static MemoryRegion *get_supported_region(MemoryRegion *mr)
{
    assert(mr != NULL);
    if (!memory_region_is_ram(mr)) {
        /* Handle simple NUMA schema of 1 subregion */
        MemoryRegion *subregion = QTAILQ_FIRST(&mr->subregions);

        /* Zero or more than one subregion is not supported */
        if (!subregion || QTAILQ_NEXT(subregion, subregions_link)) {
            return NULL;
        }

        mr = subregion;
    }

    if (!memory_region_is_ram(mr) ||
        memory_region_is_ram_device(mr) ||
        memory_region_is_rom(mr) ||
        memory_region_is_romd(mr) ||
        mr->ram_block == NULL) {
        return NULL;
    }

    /* 1) Preallocated region should not be discarded, it's already commited.
     * 2) And resizeable ram is not supported, because
     *    memory_region_allocate_system_memory allocates fixed-size only RAM. */
    if (qemu_ram_is_preallocated(mr->ram_block) ||
        qemu_ram_is_resizeable(mr->ram_block) ||
        qemu_ram_pagesize(mr->ram_block) != getpagesize()) {
        return NULL;
    }

    return mr;
}

static int mark_present_pages(
    const ZeropageScanState *zss, unsigned long *bitmap)
{
    /* See https://www.kernel.org/doc/Documentation/vm/pagemap.txt */
    const uint64_t PM_PAGE_PRESENT = 1ULL << 63;
    typedef uint64_t pagemap_entry_t;
    const size_t buf_size = 8192 * sizeof(pagemap_entry_t);
    void *buf = NULL;
    FILE *fh;
    size_t mapping_pos;
    int ret = 0;

    assert(zss);
    assert(bitmap);

    fh = fopen("/proc/self/pagemap", "rb");
    if (fh == NULL) {
        return errno;
    }

    mapping_pos =
        ((uintptr_t)zss->mem_addr >> zss->page_shift) * sizeof(pagemap_entry_t);
    if (fseeko(fh, mapping_pos, SEEK_SET) == -1) {
        ret = errno;
        goto cleanup;
    }

    buf = g_malloc(buf_size);
    if (setvbuf(fh, buf, _IOFBF, buf_size) != 0) {
        ret = errno;
        goto cleanup;
    }

    for (size_t i = 0; i < zss->pages_count; i++) {
        pagemap_entry_t pagemap_entry;
        if (fread(&pagemap_entry, sizeof(pagemap_entry), 1, fh) != 1) {
            ret = errno;
            goto cleanup;
        }
        if (pagemap_entry & PM_PAGE_PRESENT) {
            set_bit(i, bitmap);
        }
    }

cleanup:
    fclose(fh);
    g_free(buf);
    return ret;
}

static void unmark_dirty_pages(
    const ZeropageScanState *zss, unsigned long *bitmap)
{
    assert(zss);
    assert(bitmap);
    char *page_addr = zss->mem_addr;
    for (size_t i = 0; i < zss->pages_count; i++, page_addr += zss->page_size) {
        if (test_bit(i, bitmap) && !buffer_is_zero(page_addr, zss->page_size)) {
            clear_bit(i, bitmap);
        }
    }
}

static void discard_memory(ZeropageScanState *zss)
{
    int ret;

    assert(zss);
    assert(runstate_is_running());

    if (qemu_ram_dma_getref(zss->mr->ram_block)) {
        return;
    }

    ret = vm_stop(RUN_STATE_PAUSED);
    if (ret != 0) {
        /* vm_stop may fail but stops vm anyway, so do nothing just in case */
        error_report("zeropage_scan: unexpected vm_stop error: %s",
                     strerror(-ret));
        goto done;
    }

    bitmap_zero(zss->zeroed_bitmap, zss->pages_count);
    if (mark_present_pages(zss, zss->zeroed_bitmap) != 0) {
        error_report("zeropage_scan: failed to mark present pages");
        goto done;
    }
    unmark_dirty_pages(zss, zss->zeroed_bitmap);

    zss->discarded_size = 0;
    for (size_t i = 0; i < zss->pages_count; ) {
        size_t region_offset, region_size;

        /* Skip nonpresent and dirty pages */
        while (i < zss->pages_count && !test_bit(i, zss->zeroed_bitmap)) {
            i++;
        }

        /* Count present and clean pages */
        region_offset = i << zss->page_shift;
        while (i < zss->pages_count && test_bit(i, zss->zeroed_bitmap)) {
            i++;
        }

        /* Skip region if it's too small */
        region_size = (i << zss->page_shift) - region_offset;
        if (region_size < MIN_DISCARD_SIZE) {
            continue;
        }

        /* Try to discard it */
        zss->discarded_size += region_size;
        if (madvise((char *)zss->mem_addr + region_offset, region_size,
                    MADV_DONTNEED) != 0) {
            error_report("zeropage_scan: fail to discard region %p-%p: %s",
                (char *)zss->mem_addr + region_offset,
                (char *)zss->mem_addr + region_offset + region_size,
                strerror(errno));
        }
    }

done:
    vm_start();
}

static int get_rss_size(const void *addr, size_t *rss_size)
{
    size_t len = 0;
    char *line = NULL;
    bool found = false;
    FILE *fh = fopen("/proc/self/smaps", "r");
    if (fh == NULL) {
        return errno;
    }
    while (getline(&line, &len, fh) != -1) {
        uint64_t mapping_addr;
        if (sscanf(line, "%"PRIx64"-", &mapping_addr) != 1 ||
            addr != (void *)(uintptr_t)mapping_addr) {
            continue;
        }
        while (getline(&line, &len, fh) != -1) {
            size_t value;
            if (sscanf(line, "Rss: %"PRIu64" kB", &value) == 1) {
                *rss_size = value * 1024;
                found = true;
                goto done;
            }
        }
    }
done:
    free(line);
    fclose(fh);
    return found ? 0 : ENXIO;
}

static inline void schedule_timer(ZeropageScanState *zss)
{
    timer_mod(&zss->timer, qemu_clock_get_ms(clock_type) + TIMER_INTERVAL_MS);
}

static void discard_bh_callback(void *opaque)
{
    ZeropageScanState *zss = opaque;
    size_t rss_size = 0;

    assert(zeropage_scan_enabled(zss));

    zss->bh_scheduled = false;

    /*
     * Our case is running guest, because guest's RAM is being zeroed
     * by Windows (not QEMU). So check it to avoid unexpected behavior.
     * Discard memory during the migration is also dangerous, so skip it too
     */
    if (!runstate_is_running() || !migration_is_idle()) {
        return;
    }
    if (get_rss_size(zss->mem_addr, &rss_size) ||
        100 * rss_size / zss->mem_size < MIN_MEMORY_USAGE_PERCENT) {
        return;
    }

    discard_memory(zss);
    timer_del(&zss->timer);
}

static void timer_callback(void *opaque)
{
    ZeropageScanState *zss = opaque;
    int64_t vm_uptime;

    assert(zeropage_scan_enabled(zss));

    vm_uptime = qemu_clock_get_ms(clock_type) - zss->last_reset_time;
    assert(vm_uptime >= 0);
    if (vm_uptime >= zss->timeout_ms) {
        return;
    }

    if (!zss->bh_scheduled) {
        /* We do vm_stop in discard_memory() which disables virtual clocks,
        * but we can't disable virtual clock from timer callback */
        aio_bh_schedule_oneshot(qemu_get_aio_context(), discard_bh_callback,
                                zss);
        zss->bh_scheduled = true;
    }
    schedule_timer(zss);
}

static void reset_handler(void *opaque)
{
    ZeropageScanState *zss = opaque;
    zss->last_reset_time = qemu_clock_get_ms(clock_type);
    zss->discarded_size = -1;
    schedule_timer(zss);
}

static void exit_notifier_cb(Notifier *notifier, void *data)
{
    ZeropageScanState *zss = container_of(notifier, ZeropageScanState,
                                          exit_notifier);
    zeropage_scan_cleanup(zss);
}

ZeropageScanInfo *qmp_query_zeropage_scan(Error **errp)
{
    ZeropageScanInfo *info;
    ZeropageScanState *zss = &zeropage_scan_state;

    info = g_new0(ZeropageScanInfo, 1);
    info->enabled = zeropage_scan_enabled(zss);
    info->discarded_size = zss->discarded_size;

    return info;
}
