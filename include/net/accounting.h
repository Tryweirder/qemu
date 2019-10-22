/*
 * Net accounting.
 *
 * A lot of this code is currently copy-pasted from block accounting.
 * There is a lot of common things that can be extracted for both implementations,
 * for example latency histograms.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef NET_ACCOUNTING_H
#define NET_ACCOUNTING_H

#include "qemu/thread.h"
#include "qapi/qapi-builtin-types.h"

/* Reuse block latency histograms */
#include "block/accounting.h"

typedef struct NetAcctStats {
    QemuMutex lock;
    uint64_t nr_bytes;
    uint64_t nr_in_flight;
    uint64_t nr_completed;
    uint64_t nr_dropped;
    uint64_t nr_failed;
    BlockLatencyHistogram latency_histogram;
} NetAcctStats;

typedef struct NetAcctCookie {
    int64_t start_time_ns;
} NetAcctCookie;

void net_acct_init(NetAcctStats *stats);
void net_acct_cleanup(NetAcctStats *stats);

void net_acct_start(NetAcctStats *stats, NetAcctCookie *cookie);

void net_acct_done(NetAcctStats *stats, NetAcctCookie *cookie, int64_t bytes);

void net_acct_drop(NetAcctStats *stats, NetAcctCookie *cookie);

void net_acct_fail(NetAcctStats *stats, NetAcctCookie *cookie);

int net_latency_histogram_set(NetAcctStats *stats, uint64List *boundaries);
void net_latency_histograms_clear(NetAcctStats *stats);

#endif
