#ifndef BLOCK_TRACE_H
#define BLOCK_TRACE_H

#include "qemu/thread.h"
#include "qemu/timer.h"
#include "qapi/qapi-types-yc.h"


typedef struct BlockTraceEntry {
    uint64_t bytes;
    uint64_t latency;
    BlockTraceType type;
} BlockTraceEntry;

typedef enum BlockTraceStatus {
    BLOCK_TRACE_INVALID = 0,
    BLOCK_TRACE_STARTED,
    BLOCK_TRACE_STOPPED,
    BLOCK_TRACE_FAILED
} BlockTraceStatus;

typedef struct BlockTraceState {
    QemuMutex lock;
    QEMUClockType clock_type;
    BlockTraceEntry *entries;
    uint32_t capacity;
    uint32_t count;
    BlockTraceStatus status;
} BlockTraceState;

void block_trace_init(BlockTraceState *ts);
void block_trace_cleanup(BlockTraceState *ts);
void block_trace_set_clock(BlockTraceState *ts, QEMUClockType clock_type);

uint64_t block_trace_entry_begin(BlockTraceState *ts);
void block_trace_entry_end(BlockTraceState *ts,  uint64_t start_ns,
                           BlockTraceType type, uint64_t bytes);

void block_trace_start(BlockTraceState *ts, uint32_t latency, Error **errp);
BlockTraceInfoList *block_trace_stop(BlockTraceState *ts, Error **errp);

#endif
