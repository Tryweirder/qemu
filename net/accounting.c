
#include "qemu/osdep.h"
#include "net/accounting.h"

void net_acct_init(NetAcctStats *stats)
{
    g_assert(stats);
    qemu_mutex_init(&stats->lock);
}

void net_acct_cleanup(NetAcctStats *stats)
{
    if (!stats) {
        return;
    }

    qemu_mutex_destroy(&stats->lock);
}

void net_acct_start(NetAcctStats *stats, NetAcctCookie *cookie)
{
    g_assert(stats);
    g_assert(cookie);

    cookie->start_time_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    stats->nr_in_flight++;
}

static void net_account_one_io(NetAcctStats *stats, NetAcctCookie *cookie, int64_t bytes,
                               bool dropped, bool failed)
{
    g_assert(stats);
    g_assert(cookie);

    int64_t latency_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - cookie->start_time_ns;

    qemu_mutex_lock(&stats->lock);

    stats->nr_in_flight--;
    if (dropped) {
        stats->nr_dropped++;
    } else if (failed) {
        stats->nr_failed++;
    } else {
        stats->nr_bytes += bytes;
        stats->nr_completed++;

        /* Account only for succesfull latencies */
        latency_histogram_account(&stats->latency_histogram,
                                  latency_ns);
    }

    qemu_mutex_unlock(&stats->lock);
}

void net_acct_done(NetAcctStats *stats, NetAcctCookie *cookie, int64_t bytes)
{
    net_account_one_io(stats, cookie, bytes, false, false);
}

void net_acct_drop(NetAcctStats *stats, NetAcctCookie *cookie)
{
    net_account_one_io(stats, cookie, 0, true, false);
}

void net_acct_fail(NetAcctStats *stats, NetAcctCookie *cookie)
{
    net_account_one_io(stats, cookie, 0, false, true);
}

int net_latency_histogram_set(NetAcctStats *stats, uint64List *boundaries)
{
    LatencyHistogram *hist = &stats->latency_histogram;
    return latency_histogram_set(hist, boundaries);
}

void net_latency_histograms_clear(NetAcctStats *stats)
{
    latency_histogram_clear(&stats->latency_histogram);
}
