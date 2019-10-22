/*
 * QEMU latency histogram utility
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) version 3 or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/latency-histogram.h"

/* latency_histogram_compare_func:
 * Compare @key with interval [@it[0], @it[1]).
 * Return: -1 if @key < @it[0]
 *          0 if @key in [@it[0], @it[1])
 *         +1 if @key >= @it[1]
 */
static int latency_histogram_compare_func(const void *key, const void *it)
{
    uint64_t k = *(uint64_t *)key;
    uint64_t a = ((uint64_t *)it)[0];
    uint64_t b = ((uint64_t *)it)[1];

    return k < a ? -1 : (k < b ? 0 : 1);
}

void latency_histogram_account(LatencyHistogram *hist, int64_t latency_ns)
{
    uint64_t *pos;

    if (hist->bins == NULL) {
        /* histogram disabled */
        return;
    }


    if (latency_ns < hist->boundaries[0]) {
        hist->bins[0]++;
        return;
    }

    if (latency_ns >= hist->boundaries[hist->nbins - 2]) {
        hist->bins[hist->nbins - 1]++;
        return;
    }

    pos = bsearch(&latency_ns, hist->boundaries, hist->nbins - 2,
                  sizeof(hist->boundaries[0]),
                  latency_histogram_compare_func);
    assert(pos != NULL);

    hist->bins[pos - hist->boundaries + 1]++;
}

int latency_histogram_set(LatencyHistogram *hist, uint64List *boundaries)
{
    uint64List *entry;
    uint64_t *ptr;
    uint64_t prev = 0;
    int new_nbins = 1;

    for (entry = boundaries; entry; entry = entry->next) {
        if (entry->value <= prev) {
            return -EINVAL;
        }
        new_nbins++;
        prev = entry->value;
    }

    hist->nbins = new_nbins;
    g_free(hist->boundaries);
    hist->boundaries = g_new(uint64_t, hist->nbins - 1);
    for (entry = boundaries, ptr = hist->boundaries; entry;
         entry = entry->next, ptr++)
    {
        *ptr = entry->value;
    }

    g_free(hist->bins);
    hist->bins = g_new0(uint64_t, hist->nbins);

    return 0;
}

void latency_histogram_clear(LatencyHistogram *hist)
{
    if (!hist) {
        return;
    }

    g_free(hist->bins);
    g_free(hist->boundaries);
    memset(hist, 0, sizeof(*hist));
}

static uint64List *uint64_list(uint64_t *array, int size)
{
    int i;
    uint64List *out_list = NULL;
    uint64List **pout_list = &out_list;

    for (i = 0; i < size; i++) {
        uint64List *entry = g_new(uint64List, 1);
        entry->value = array[i];
        *pout_list = entry;
        pout_list = &entry->next;
    }

    *pout_list = NULL;

    return out_list;
}

LatencyHistogramInfo *latency_histogram_info(const LatencyHistogram *hist)
{
    if (!hist || !hist->bins) {
        return NULL;
    }

    LatencyHistogramInfo *hinfo = g_malloc0(sizeof(*hinfo));
    hinfo->boundaries = uint64_list(hist->boundaries, hist->nbins - 1);
    hinfo->bins = uint64_list(hist->bins, hist->nbins);

    return hinfo;
}

void latency_histogram_accumulate(LatencyHistogram *accumulated_hist,
                                  const LatencyHistogram *hist)
{
    if (!hist || !hist->bins || !accumulated_hist) {
        return;
    }

    if (!accumulated_hist->bins) {
        accumulated_hist->nbins = hist->nbins;
        accumulated_hist->boundaries = g_memdup(hist->boundaries,
            sizeof(uint64_t) * (hist->nbins - 1));
        accumulated_hist->bins = g_memdup(hist->bins,
            sizeof(uint64_t) * hist->nbins);
    } else {
        /* can only accumulate histograms with same boundaries */
        if (accumulated_hist->nbins != hist->nbins) {
            return;
        }

        int i;
        for (i = 0; i < accumulated_hist->nbins; ++i) {
            if (i != (accumulated_hist->nbins - 1) &&
                accumulated_hist->boundaries[i] != hist->boundaries[i]) {
                return;
            }
            accumulated_hist->bins[i] += hist->bins[i];
        }
    }
}
