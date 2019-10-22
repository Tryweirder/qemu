#include "qemu/osdep.h"
#include "block/block-trace.h"
#include "qemu/timer.h"
#include "qapi/error.h"

#define BLK_TRACE_INITIALIZED(ts) ((ts) && (ts)->status != BLOCK_TRACE_INVALID)

void block_trace_init(BlockTraceState *ts)
{
    assert(ts);
    qemu_mutex_init(&ts->lock);
    ts->clock_type = QEMU_CLOCK_REALTIME;
    ts->entries = NULL;
    ts->count = 0;
    ts->capacity = 0;
    ts->status = BLOCK_TRACE_STOPPED;
}

static void block_trace_entries_free(BlockTraceState *ts)
{
    g_free(ts->entries);
    ts->entries = NULL;
    ts->count = 0;
    ts->capacity = 0;
}

void block_trace_cleanup(BlockTraceState *ts)
{
    if (!BLK_TRACE_INITIALIZED(ts)) {
        return;
    }

    block_trace_entries_free(ts);
    qemu_mutex_destroy(&ts->lock);
    ts->status = BLOCK_TRACE_INVALID;
}

void block_trace_set_clock(BlockTraceState *ts, QEMUClockType clock_type)
{
    assert(BLK_TRACE_INITIALIZED(ts) && ts->status != BLOCK_TRACE_STARTED);
    ts->clock_type = clock_type;
}

uint64_t block_trace_entry_begin(BlockTraceState *ts)
{
    assert(BLK_TRACE_INITIALIZED(ts));
    return ts->status == BLOCK_TRACE_STARTED ?
           qemu_clock_get_ns(ts->clock_type) : 0;
}

void block_trace_entry_end(BlockTraceState *ts,  uint64_t start_ns,
                           BlockTraceType type, uint64_t bytes)
{
    if (start_ns == 0) {
        return;
    }

    assert(BLK_TRACE_INITIALIZED(ts));
    qemu_mutex_lock(&ts->lock);
    if (ts->status == BLOCK_TRACE_STARTED) {
        if (ts->count < ts->capacity) {
            BlockTraceEntry *entry;
            entry = &ts->entries[ts->count];
            entry->bytes = bytes;
            entry->latency = qemu_clock_get_ns(ts->clock_type) - start_ns;
            entry->type = type;
            ts->count++;
        } else {
            ts->status = BLOCK_TRACE_FAILED;
            block_trace_entries_free(ts);
        }
    }
    qemu_mutex_unlock(&ts->lock);
}

void block_trace_start(BlockTraceState *ts, uint32_t capacity, Error **errp)
{
    assert(BLK_TRACE_INITIALIZED(ts));
    qemu_mutex_lock(&ts->lock);
    if (ts->status != BLOCK_TRACE_STOPPED) {
        error_setg(errp, "Trace is already started");
    } else if (capacity == 0) {
        error_setg(errp, "Invalid capacity value");
    } else {
        assert(ts->entries == NULL);
        ts->entries = g_new(BlockTraceEntry, capacity);
        ts->capacity = capacity;
        ts->count = 0;
        ts->status = BLOCK_TRACE_STARTED;
    }
    qemu_mutex_unlock(&ts->lock);
}

static int entry_compare_func(const void *entry_a, const void *entry_b)
{
    const BlockTraceEntry *a = entry_a;
    const BlockTraceEntry *b = entry_b;
    /* Sorting by the entry type is used for computing percentiles
     * in the block_trace_query. */
    if (a->type != b->type) {
        return a->type < b->type ? -1 : 1;
    }
    if (a->latency != b->latency) {
        return a->latency < b->latency ? -1 : 1;
    }
    return 0;
}

/* Called with trace lock held. */
static BlockTraceInfoList *block_trace_query(BlockTraceState *ts)
{
    BlockTraceInfoList *head = NULL;
    BlockTraceInfoList **p_next = &head;
    BlockTraceEntry *entry, *entries_end;
    BlockTraceInfo *infos[BLOCK_TRACE_TYPE__MAX];
    const int percentiles[] = {
        1, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 99
    };
    uint32_t offset;

    for (size_t i = 0; i < ARRAY_SIZE(infos); i++) {
        BlockTraceInfoList *list_item = g_new0(BlockTraceInfoList, 1);
        list_item->value = g_new0(BlockTraceInfo, 1);
        *list_item->value = (BlockTraceInfo) {
            .type = (BlockTraceType)i
        };

        *p_next = list_item;
        p_next = &list_item->next;
        infos[i] = list_item->value;
    }

    /* Compute general info */
    entries_end = ts->entries + ts->count;
    for (entry = ts->entries; entry != entries_end; entry++) {
        infos[entry->type]->count++;
        infos[entry->type]->size += entry->bytes;
        infos[entry->type]->latency += entry->latency;
    }

    /* Compute percentiles */
    qsort(ts->entries, ts->count, sizeof(ts->entries[0]), entry_compare_func);
    offset = 0;
    for (size_t i = 0; i < ARRAY_SIZE(infos); i++) {
        BlockTracePercentileList *head = NULL;
        BlockTracePercentileList **p_next = &head;
        BlockTracePercentileList *list_item;
        BlockTraceInfo *info = infos[i];

        if (info->count == 0) {
            continue;
        }

        for (size_t j = 0; j < ARRAY_SIZE(percentiles); j++) {
            size_t index = offset + percentiles[j] * info->count / 100;
            uint64_t latency = ts->entries[index].latency;

            list_item = g_new0(BlockTracePercentileList, 1);
            list_item->value = g_new0(BlockTracePercentile, 1);
            *list_item->value = (BlockTracePercentile) {
                .latency = latency,
                .percentile = percentiles[j]
            };

            *p_next = list_item;
            p_next = &list_item->next;
        }

        info->percentiles = head;
        offset += info->count;
    }

    return head;
}

BlockTraceInfoList *block_trace_stop(BlockTraceState *ts, Error **errp)
{
    BlockTraceInfoList *result = NULL;
    assert(BLK_TRACE_INITIALIZED(ts));
    qemu_mutex_lock(&ts->lock);
    switch (ts->status) {
    case BLOCK_TRACE_STARTED:
        ts->status = BLOCK_TRACE_STOPPED;
        result = block_trace_query(ts);
        block_trace_entries_free(ts);
        break;
    case BLOCK_TRACE_STOPPED:
        error_setg(errp, "Trace is already stopped");
        break;
    case BLOCK_TRACE_FAILED:
        ts->status = BLOCK_TRACE_STOPPED;
        error_setg(errp, "Trace was failed and stopped automatically");
        break;
    default:
        assert(FALSE);
        break;
    }
    qemu_mutex_unlock(&ts->lock);
    return result;
}
