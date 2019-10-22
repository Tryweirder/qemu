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

#ifndef LATENCY_HISTOGRAM_H
#define LATENCY_HISTOGRAM_H

#include "qapi/qapi-types-common.h"

typedef struct LatencyHistogram {
    /* The following histogram is represented like this:
     *
     * 5|           *
     * 4|           *
     * 3| *         *
     * 2| *         *    *
     * 1| *    *    *    *
     *  +------------------
     *      10   50   100
     *
     * BlockLatencyHistogram histogram = {
     *     .nbins = 4,
     *     .boundaries = {10, 50, 100},
     *     .bins = {3, 1, 5, 2},
     * };
     *
     * @boundaries array define histogram intervals as follows:
     * [0, boundaries[0]), [boundaries[0], boundaries[1]), ...
     * [boundaries[nbins-2], +inf)
     *
     * So, for example above, histogram intervals are:
     * [0, 10), [10, 50), [50, 100), [100, +inf)
     */
    int nbins;
    uint64_t *boundaries; /* @nbins-1 numbers here
                             (all boundaries, except 0 and +inf) */
    uint64_t *bins;
} LatencyHistogram;

int latency_histogram_set(LatencyHistogram *hist, uint64List *boundaries);
void latency_histogram_clear(LatencyHistogram *hist);

void latency_histogram_account(LatencyHistogram *hist, int64_t latency_ns);

LatencyHistogramInfo *latency_histogram_info(const LatencyHistogram *hist);

void latency_histogram_accumulate(LatencyHistogram *accumulated_hist,
                                  const LatencyHistogram *hist);

#endif
