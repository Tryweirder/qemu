/*
 * QEMU block plugin format
 *
 * Pluggable driver allows to delegate implementation of block device to
 * an external shared object, so that it could be written in another programming
 * language or infrastructure than QEMU itself.
 *
 * Copyright Yandex N.V., 2017
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <dlfcn.h>

#include "qemu/osdep.h"
#include "block/block_int.h"
#include "block/block-trace.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-yc.h"
#include "qapi/qmp/qstring.h"
#include "qapi/qmp/qdict.h"
#include "qemu/option.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "sysemu/block-backend.h"
#include "trace.h"

#include "blockstore-plugin.h"

#if defined(_DEBUG)
#   define TRACE(fmt, ...) \
        fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__);
#else
#   define TRACE(fmt, ...)
#endif

/* We do not support APIs whose minor version is lower than this */
#define BLOCK_PLUGIN_API_VERSION_MINOR_COMPAT  0x2

#define MOUNT_TOKEN_MAX_SIZE        ((size_t)128)

#define PATH_ARGUMENT_NAME          "impl_path"
#define VOLUME_ARGUMENT_NAME        "impl_volume"
#define OPTIONS_ARGUMENT_NAME       "impl_options"
#define MOUNT_TOKEN_ARGUMENT_NAME   "impl_mount_token_path"

static BlockDriver bdrv_pluggable;

typedef struct CompletionEntry {
    struct BlockPlugin_Completion comp;
    BlockDriverState *bs;
    Coroutine *co;
    QSIMPLEQ_ENTRY(CompletionEntry) link;

    /* Fast completion sequence lock */
    uint32_t seqlock;
} CompletionEntry;

typedef struct BDRVPluggableState {
    /* Args */
    const char *impl_path;
    const char *impl_volume;
    const char *impl_options;
    const char *impl_mount_token_path;

    /* Plugin DSO handle */
    void *impl_handle;

    /* Plugin volume representation */
    bool is_mounted;
    struct BlockPlugin_Volume volume;
    struct BlockPlugin *plugin;

    /* Bottom half scheduled to process completions */
    QEMUBH *completion_bh;
    QSIMPLEQ_HEAD(, CompletionEntry) completion_queue;
    QemuMutex queue_lock;

    /* Perf tracing context */
    BlockTraceState trace_state;

    /* Saved mount token buffer, if any */
    void *mount_token;

    /* Waiting for completion of async mount or unmount */
    volatile bool in_async_transition;

    /* Return EIO for write/read requests to test bdev */
    bool fail_writes;
    bool fail_reads;
} BDRVPluggableState;

#define BS_TO_PLUGGABLE_STATE(bs) ((BDRVPluggableState *)bs->opaque)

static inline bool is_write_request(struct BlockPlugin_Request *req)
{
    return req->type == BLOCK_PLUGIN_WRITE_BLOCKS ||
           req->type == BLOCK_PLUGIN_ZERO_BLOCKS;
}

static inline bool is_read_request(struct BlockPlugin_Request *req)
{
    return req->type == BLOCK_PLUGIN_READ_BLOCKS;
}

static int complete_request(
    struct BlockPluginHost *bp,
    struct BlockPlugin_Completion *completion);

static void log_message(struct BlockPluginHost *bp, const char *msg)
{
    if (msg) {
        error_report("%s", msg);
    }
}

static struct BlockPluginHost gBlockPluginHost = {
    .magic = BLOCK_PLUGIN_HOST_MAGIC,
    .version_major = BLOCK_PLUGIN_API_VERSION_MAJOR,
    .version_minor = BLOCK_PLUGIN_API_VERSION_MINOR,
    .complete_request = complete_request,
    .log_message = log_message,
};

QEMU_BUILD_BUG_ON(sizeof(struct BlockPlugin_IOVector) !=
                  sizeof(struct QEMUIOVector));

static QemuOptsList pluggable_opts = {
    .name = "pluggable-opts",
    .head = QTAILQ_HEAD_INITIALIZER(pluggable_opts.head),
    .desc = {
        {
            .name = PATH_ARGUMENT_NAME,
            .type = QEMU_OPT_STRING,
            .help = "path to implementation shared object",
        },
        {
            .name = VOLUME_ARGUMENT_NAME,
            .type = QEMU_OPT_STRING,
            .help = "volume passed to implementation shared object",
        },
        {
            .name = OPTIONS_ARGUMENT_NAME,
            .type = QEMU_OPT_STRING,
            .help = "options passed to implementation shared object",
        },
        {
            .name = MOUNT_TOKEN_ARGUMENT_NAME,
            .type = QEMU_OPT_STRING,
            .help = "path to a file that contains mount token for this volume",
        },

        { /* end of list */ }
    },
};

static int pluggable_read_options(
    QDict *options,
    BlockDriverState *bs,
    BDRVPluggableState *s,
    Error **errp)
{
    int ret = 0;

    Error *local_err = NULL;
    QemuOpts *opts = NULL;

    opts = qemu_opts_create(&pluggable_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto end;
    }

    const char *impl_path = qemu_opt_get(opts, PATH_ARGUMENT_NAME);
    if (impl_path == NULL) {
        error_setg(errp,
            "One must specify 'impl_path' option for pluggable driver");
        ret = -EINVAL;
        goto end;
    }

    const char *impl_volume = qemu_opt_get(opts, VOLUME_ARGUMENT_NAME);
    if (impl_volume == NULL) {
        error_setg(errp,
            "One must specify 'impl_volume' option for pluggable driver");
        ret = -EINVAL;
        goto end;
    }

    s->impl_path = g_strdup(impl_path);
    s->impl_volume = g_strdup(impl_volume);

    /* These are optional and may be NULL */
    const char *impl_options = qemu_opt_get(opts, OPTIONS_ARGUMENT_NAME);
    const char *mount_token_path = qemu_opt_get(opts,
                                                MOUNT_TOKEN_ARGUMENT_NAME);

    s->impl_options = g_strdup(impl_options);
    s->impl_mount_token_path = g_strdup(mount_token_path);

end:
    qemu_opts_del(opts);
    return ret;
}

static CompletionEntry *dequeue_completion(BDRVPluggableState *s)
{
    assert(s);

    CompletionEntry *entry = NULL;

    qemu_mutex_lock(&s->queue_lock);
    if (!QSIMPLEQ_EMPTY(&s->completion_queue)) {
        entry = QSIMPLEQ_FIRST(&s->completion_queue);
        QSIMPLEQ_REMOVE_HEAD(&s->completion_queue, link);
    }
    qemu_mutex_unlock(&s->queue_lock);

    return entry;
}

static void enqueue_completion(BDRVPluggableState *s, CompletionEntry *e)
{
    assert(s);
    assert(e);

    qemu_mutex_lock(&s->queue_lock);
    QSIMPLEQ_INSERT_TAIL(&s->completion_queue, e, link);
    qemu_mutex_unlock(&s->queue_lock);

    qemu_bh_schedule(s->completion_bh); /* BH schedule is thread-safe */
}

static uint64_t trace_begin(BDRVPluggableState *s)
{
    return block_trace_entry_begin(&s->trace_state);
}

static void trace_end(BDRVPluggableState *s, struct BlockPlugin_Request *req,
                      uint64_t start_ns)
{
    switch (req->type) {
    case BLOCK_PLUGIN_READ_BLOCKS: {
        uint64_t size = ((struct BlockPlugin_ReadBlocks *)req)->bp_iov->size;
        block_trace_entry_end(&s->trace_state, start_ns,
                              BLOCK_TRACE_TYPE_READ, size);
        break;
    }
    case BLOCK_PLUGIN_WRITE_BLOCKS: {
        uint64_t size = ((struct BlockPlugin_WriteBlocks *)req)->bp_iov->size;
        block_trace_entry_end(&s->trace_state, start_ns,
                              BLOCK_TRACE_TYPE_WRITE, size);
        break;
    }
    default:
        break;
    }
}

/* Submit generic request to plugin and yield waiting for completion */
static int coroutine_fn submit_request(
    BlockDriverState *bs,
    struct BlockPlugin_Request *req)
{
    assert(bs);
    assert(req);

    BDRVPluggableState *s = bs->opaque;

    assert(qemu_in_coroutine());

    if ((s->fail_writes && is_write_request(req)) ||
        (s->fail_reads && is_read_request(req))) {
        return -EIO;
    }

    CompletionEntry *entry = g_new0(CompletionEntry, 1);
    entry->co = qemu_coroutine_self();
    entry->bs = bs;
    entry->comp.custom_data = entry;
    entry->comp.status = BP_COMPLETION_INVALID;

    uint64_t start_ns = trace_begin(s);
    int ret = s->plugin->submit_request(s->plugin, &s->volume, req,
                                        &entry->comp);
    if (ret != 0) {
        goto end;
    }

    int comp_status = entry->comp.status;
    if (comp_status == BP_COMPLETION_INVALID) {
        /*
         * A bit of defensive code - let's verify that plugin
         * follows its contract here and not go into yield forever
         */
        ret = -EIO;
        goto end;
    }

    /*
     * It is possible to have completion ready by this point if plugin managed
     * to handle it fast enough
     * To avoid racing with concurrent completion thread we use a sequence lock
     * as follows:
     * 0->1: iothread thread (this one) notified completion thread that it has
     * observed request status as completed
     * 1->2: completion thread acks iothread observation and takes ownership of
     * completion entry pointer
     */
    if (comp_status != BP_COMPLETION_INPROGRESS) {
        if (atomic_inc_fetch(&entry->seqlock) == 1) {
            entry = NULL; /* Completion thread now owns this pointer,
                           * set it to NULL to catch bugs */
            goto completed;
        }
    }

    qemu_coroutine_yield();
    comp_status = entry->comp.status;

completed:
    if (comp_status == BP_COMPLETION_ERROR) {
        ret = -EIO;
    } else {
        trace_end(s, req, start_ns);
    }

end:
    g_free(entry);
    return ret;
}

/* Called in iothread as a bottom half to process completion queue */
static void completion_bh_worker(void *opaque)
{
    BDRVPluggableState *s = opaque;
    assert(s);

    CompletionEntry *entry = NULL;
    while ((entry = dequeue_completion(s)) != NULL) {
        aio_co_wake(entry->co);
    }
}

/* Will be called from plugin thread (i.e. concurrently with block iothread) */
static int complete_request(
    struct BlockPluginHost *bp,
    struct BlockPlugin_Completion *completion)
{
    assert(bp);
    assert(completion);

    CompletionEntry *entry = completion->custom_data;
    BlockDriverState *bs = entry->bs;
    BDRVPluggableState *s = bs->opaque;

    if (qemu_in_coroutine() && qemu_coroutine_self() == entry->co) {
        /*
         * Fast completion from the same thread - no need to schedule anything
         * No idea if that is possible by plugin but it sure is nice to have
         */
        return 0;
    }

    if (atomic_inc_fetch(&entry->seqlock) == 2) {
        /*
         * Submission thread already observed that request has been completed.
         * We now own completion entry pointer and are responsible to free it
         */
        g_free(entry);
        return 0;
    }

    /*
     * Putting entry in completion queue means releasing ownership
     * Don't use entry after that, it may have been freed in iothread already
     * TODO: just use qobject refcounting for this,
     * it will make it so much easier...
     */
    if (s->in_async_transition) {
        aio_co_schedule(bdrv_get_aio_context(bs), entry->co);
    } else {
        enqueue_completion(bs->opaque, entry);
    }
    return 0;
}

/* Convert fixed-sized bdrv sectors to what blockstore volume wants */
static uint64_t bdrv_to_blockstore_sectors(BDRVPluggableState *s,
                                           uint64_t sectors)
{
    /*
     * BDRV should see our block size and should not send us requests
     * that overflow in byte size. Assert that.
     */
    assert((sectors << BDRV_SECTOR_BITS) >> BDRV_SECTOR_BITS == sectors);
    return (sectors << BDRV_SECTOR_BITS) / s->volume.block_size;
}

static coroutine_fn int pluggable_co_writev(
    BlockDriverState *bs,
    int64_t sector_num,
    int sectors,
    QEMUIOVector *qiov)
{
    BDRVPluggableState *s = bs->opaque;
    struct BlockPlugin_WriteBlocks req;

    trace_pluggable_co_writev(sector_num, sectors, s->fail_writes);

    req.header.type = BLOCK_PLUGIN_WRITE_BLOCKS;
    req.header.size = sizeof(req);
    req.start_index = bdrv_to_blockstore_sectors(bs->opaque, sector_num);
    req.blocks_count = bdrv_to_blockstore_sectors(bs->opaque, sectors);
    req.bp_iov = (struct BlockPlugin_IOVector *)qiov;

    return submit_request(bs, &req.header);
}

static coroutine_fn int pluggable_co_readv(
    BlockDriverState *bs,
    int64_t sector_num,
    int sectors,
    QEMUIOVector *qiov)
{
    BDRVPluggableState *s = bs->opaque;
    struct BlockPlugin_ReadBlocks req;

    trace_pluggable_co_readv(sector_num, sectors, s->fail_reads);

    req.header.type = BLOCK_PLUGIN_READ_BLOCKS;
    req.header.size = sizeof(req);
    req.start_index = bdrv_to_blockstore_sectors(bs->opaque, sector_num);
    req.blocks_count = bdrv_to_blockstore_sectors(bs->opaque, sectors);
    req.bp_iov = (struct BlockPlugin_IOVector *)qiov;

    return submit_request(bs, &req.header);
}

static int coroutine_fn pluggable_co_pwrite_zeroes(
    BlockDriverState *bs,
    int64_t offset,
    int count,
    BdrvRequestFlags flags)
{
    BDRVPluggableState *s = bs->opaque;
    struct BlockPlugin_ZeroBlocks req;

    trace_pluggable_co_pwrite_zeroes(offset, count, s->fail_writes);

    /* BDRV should respect our request alignment */
    if (!QEMU_IS_ALIGNED(offset, s->volume.block_size) ||
        !QEMU_IS_ALIGNED(count, s->volume.block_size)) {
        return -EINVAL;
    }

    req.header.type = BLOCK_PLUGIN_ZERO_BLOCKS;
    req.header.size = sizeof(req);
    req.start_index = offset / s->volume.block_size;
    req.blocks_count = count / s->volume.block_size;

    /*
     * We don't care about flags here since we haven't reported any
     * additional zero features (unmap, etc).
     */
    return submit_request(bs, &req.header);
}

/* Read NBS mount token from file at given path */
static int read_mount_token(const char *path, char *buf, size_t bufsize)
{
    assert(path);
    assert(buf);
    assert(bufsize);

    int ret = 0;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -errno;
    }

    ret = fseek(fp, 0, SEEK_END);
    if (ret != 0) {
        ret = -errno;
        goto out;
    }

    long fsize = ftell(fp);
    if (fsize < 0) {
        ret = -errno;
        goto out;
    }

    ret = fseek(fp, 0, SEEK_SET);
    if (ret != 0) {
        ret = -errno;
        goto out;
    }

    /* bufsize includes space for null terminator */
    if (fsize >= bufsize) {
        ret = -ENOSPC;
        goto out;
    }

    if (fsize != fread(buf, 1, fsize, fp)) {
        ret = -errno;
        goto out;
    }

    /* Trim trailing whitespaces in tokens for convinience */
    char *end = buf + fsize;
    do {
        --end;
    } while (end >= buf && isspace(*end));
    end[1] = '\0';

out:
    fclose(fp);
    return ret;
}

/*
 * Release resources associated with pluggable state
 * Can work with partially initialized state
 */
static void pluggable_close(BlockDriverState *bs)
{
    BDRVPluggableState *s = bs->opaque;

    g_free((void *)s->impl_path);
    g_free((void *)s->impl_options);
    g_free((void *)s->impl_mount_token_path);

    if (s->plugin) {
        if (s->is_mounted) {
            if (qemu_in_coroutine()) {
                int ret;

                CompletionEntry entry;
                entry.co = qemu_coroutine_self();
                entry.bs = bs;
                entry.comp.custom_data = &entry;
                entry.comp.status = BP_COMPLETION_INVALID;

                s->in_async_transition = true;
                ret = s->plugin->umount_async(s->plugin, &s->volume,
                                              &entry.comp);
                if (ret == BLOCK_PLUGIN_E_OK) {
                    /* wait for completion from plugin */
                    qemu_coroutine_yield();

                    if (entry.comp.status != BP_COMPLETION_UNMOUNT_FINISHED) {
                        error_report("Async unmount of volume %s "
                                     "has unexpected completion status %d",
                                     s->impl_volume, entry.comp.status);
                    }
                } else {
                    error_report("Async unmount of volume %s returned error %d",
                                 s->impl_volume, ret);
                }
                s->in_async_transition = false;
            } else {
                s->plugin->umount(s->plugin, &s->volume);
            }
        }

        BlockPlugin_PutPlugin_t put_plugin = dlsym(
            s->impl_handle,
            BLOCK_PLUGIN_PUT_PLUGIN_SYMBOL_NAME);
        g_assert(put_plugin);
        put_plugin(s->plugin);
    }

    g_free((void *)s->impl_volume);

    if (s->impl_handle) {
        dlclose(s->impl_handle);
        s->impl_handle = NULL;
    }

    if (s->mount_token) {
        qemu_secure_zero_memory(s->mount_token, strlen(s->mount_token));
        g_free(s->mount_token);
    }

    /* No requests should be in flight at this time */
    if (s->completion_bh) {
        assert(QSIMPLEQ_EMPTY(&s->completion_queue));
        qemu_bh_delete(s->completion_bh);
        qemu_mutex_destroy(&s->queue_lock);
    }

    block_trace_cleanup(&s->trace_state);

    memset(s, 0, sizeof(*s));
}

static int pluggable_open(
    BlockDriverState *bs,
    QDict *options,
    int flags,
    Error **errp)
{
    BDRVPluggableState *s = bs->opaque;
    int ret;

    bool async = qdict_get_try_bool(options, "async", false);
    qdict_del(options, "async");

    ret = pluggable_read_options(options, bs, s, errp);
    if (ret < 0) {
        return ret;
    }

    s->fail_writes = false;
    s->fail_reads = false;

    s->impl_handle = dlopen(s->impl_path, RTLD_NOW | RTLD_LOCAL);
    if (!s->impl_handle) {
        error_setg(errp, "Cannot open impl shared object: %s", dlerror());
        return -EINVAL;
    }

    /*
     * Need to cleanup partially initialized pluggable state from this point on
     */

    BlockPlugin_GetPlugin_t get_plugin = dlsym(
        s->impl_handle,
        BLOCK_PLUGIN_GET_PLUGIN_SYMBOL_NAME);

    BlockPlugin_PutPlugin_t put_plugin = dlsym(
        s->impl_handle,
        BLOCK_PLUGIN_PUT_PLUGIN_SYMBOL_NAME);

    if (!get_plugin || !put_plugin) {
        error_setg(errp, "Bad plugin exports: %s", dlerror());
        ret = -EINVAL;
        goto error_out;
    }

    s->plugin = get_plugin(&gBlockPluginHost,
                           (s->impl_options ? s->impl_options : ""));
    if (!s->plugin) {
        error_setg(errp, "Cannot get plugin");
        ret = -ENXIO;
        goto error_out;
    }

    if (s->plugin->magic != BLOCK_PLUGIN_MAGIC) {
        error_setg(errp, "Invalid plugin magic");
        ret = -EINVAL;
        goto error_out;
    }

    if (s->plugin->version_major != BLOCK_PLUGIN_API_VERSION_MAJOR ||
        s->plugin->version_minor < BLOCK_PLUGIN_API_VERSION_MINOR_COMPAT) {
        error_setg(errp,
            "Incompatible plugin version %d.%d, "
                "minimal supported version is %d.%d",
            s->plugin->version_major,
            s->plugin->version_minor,
            BLOCK_PLUGIN_API_VERSION_MAJOR,
            BLOCK_PLUGIN_API_VERSION_MINOR_COMPAT);
        ret = -ENOTSUP;
        goto error_out;
    }

    if (s->impl_mount_token_path != NULL) {
        char token_buf[MOUNT_TOKEN_MAX_SIZE + 1] = {0};
        ret = read_mount_token(
            s->impl_mount_token_path,
            token_buf,
            sizeof(token_buf));
        if (ret != 0) {
            error_setg(errp, "Could not read mount token from %s: %d",
                s->impl_mount_token_path,
                ret);
            goto error_out;
        }

        s->mount_token = g_strdup(token_buf);
        qemu_secure_zero_memory(token_buf, sizeof(token_buf));
    }

    struct BlockPlugin_MountOpts opts = {
        .volume_name = s->impl_volume,
        .mount_token = s->mount_token,
        .instance_id = qemu_get_vm_name(),
        .access_mode = BLOCK_PLUGIN_ACCESS_READ_WRITE,
        .mount_mode  = BLOCK_PLUGIN_MOUNT_LOCAL,
    };

    /* We're the target of migration. Mount as RO until migration is complete */
    if (bs->open_flags & BDRV_O_INACTIVE) {
        opts.access_mode = BLOCK_PLUGIN_ACCESS_READ_ONLY;
        opts.mount_mode = BLOCK_PLUGIN_MOUNT_REMOTE;
    }

    if (async) {
        assert(qemu_in_coroutine());

        CompletionEntry entry;
        entry.co = qemu_coroutine_self();
        entry.bs = bs;
        entry.comp.custom_data = &entry;
        entry.comp.status = BP_COMPLETION_INVALID;

        s->in_async_transition = true;
        ret = s->plugin->mount_async(s->plugin, &opts, &s->volume, &entry.comp);
        if (ret == BLOCK_PLUGIN_E_OK) {
            /* wait for completion from plugin */
            qemu_coroutine_yield();

            if (entry.comp.status != BP_COMPLETION_MOUNT_FINISHED) {
                ret = -EINVAL;
            }
        }
        s->in_async_transition = false;
    } else {
        ret = s->plugin->mount_sync(s->plugin, &opts, &s->volume);
    }

    if (ret != BLOCK_PLUGIN_E_OK) {
        error_setg(errp, "Volume mount failed with status %d", ret);
        ret = -EIO;
        goto error_out;
    }

    s->is_mounted = true;

    if (!QEMU_IS_ALIGNED(s->volume.block_size, BDRV_SECTOR_SIZE)) {
        error_setg(errp, "Invalid volume block size");
        ret = -EINVAL;
        goto error_out;
    }

    if (s->volume.blocks_count == 0)  {
        error_setg(errp, "Invalid volume blocks count");
        ret = -EINVAL;
        goto error_out;
    }

    if (!QEMU_IS_ALIGNED(s->volume.max_transfer, s->volume.block_size)) {
        error_setg(errp, "Invalid volume max transfer limit");
        ret = -EINVAL;
        goto error_out;
    }

    if (!QEMU_IS_ALIGNED(s->volume.opt_transfer, s->volume.block_size)) {
        error_setg(errp, "Invalid volume opt transfer limit");
        ret = -EINVAL;
        goto error_out;
    }

    bs->total_sectors =
        s->volume.block_size / BDRV_SECTOR_SIZE * s->volume.blocks_count;

    QSIMPLEQ_INIT(&s->completion_queue);
    qemu_mutex_init(&s->queue_lock);
    block_trace_init(&s->trace_state);
    /* check that no completion_bh is set */
    assert(s->completion_bh == NULL);
    s->completion_bh = aio_bh_new(
        bdrv_get_aio_context(bs),
        completion_bh_worker,
        s);

    return 0;

error_out:
    pluggable_close(bs);
    return ret;
}

static void pluggable_refresh_limits(BlockDriverState *bs, Error **errp)
{
    BDRVPluggableState *s = bs->opaque;
    uint64_t block_size = MAX(BDRV_SECTOR_SIZE, s->volume.block_size);

    bs->bl.request_alignment = block_size;
    bs->bl.max_transfer = s->volume.max_transfer;
    bs->bl.opt_transfer = s->volume.opt_transfer;

    /*
     * We don't care yet about any other limits, so leave default values
     * We might care about mem alignment after moving to shared memory IPC
     */
}

static int pluggable_probe_blocksizes(BlockDriverState *bs, BlockSizes *bsz)
{
    BDRVPluggableState *s = bs->opaque;

    /* Legacy BIOS wants to see 512 byte logical blocks */
    bsz->log = BDRV_SECTOR_SIZE;
    bsz->phys = s->volume.block_size;

    return 0;
}

static int pluggable_probe_geometry(BlockDriverState *bs, HDGeometry *geo)
{
    const uint64_t max_sectors = 255;
    const uint64_t max_heads = 255;
    const uint64_t max_cylinders = 65535;
    uint64_t sectors, heads, cylinders;

    assert(bs->total_sectors > 0);

    sectors = bs->total_sectors;
    heads = 1 + (bs->total_sectors - 1) / max_sectors;
    cylinders = 1 + (bs->total_sectors - 1) / (max_sectors * max_heads);

    geo->sectors = MIN(max_sectors, sectors);
    geo->heads = MIN(max_heads, heads);
    geo->cylinders = MIN(max_cylinders, cylinders);

    assert(geo->sectors * geo->heads * geo->cylinders >=
           MIN(bs->total_sectors, max_sectors * max_heads * max_cylinders));

    return 0;
}

static void pluggable_attach_aio_context(BlockDriverState *bs,
                                         AioContext *new_context)
{
    BDRVPluggableState *s = bs->opaque;

    assert(QSIMPLEQ_EMPTY(&s->completion_queue));
    assert(s->completion_bh == NULL);

    s->completion_bh = aio_bh_new(new_context, completion_bh_worker, s);
}

static void pluggable_detach_aio_context(BlockDriverState *bs)
{
    BDRVPluggableState *s = bs->opaque;

    assert(QSIMPLEQ_EMPTY(&s->completion_queue));
    assert(s->completion_bh != NULL);

    qemu_bh_delete(s->completion_bh);
    s->completion_bh = NULL;
}

/******************************************************************************/

/*
 * QAPI stuff
 */

static bool is_pluggable_state(BlockDriverState *bs)
{
    return (bs->drv &&
            strcmp(bs->drv->format_name, bdrv_pluggable.format_name) == 0);
}

static BlockDriverState *get_pluggable_state(const char *device, Error **errp)
{
    BlockDriverState *bs = bdrv_lookup_bs(device, NULL, NULL);
    if (!bs) {
        /* Try using node name */
        bs = bdrv_lookup_bs(NULL, device, NULL);
        if (!bs) {
            error_setg(errp, "Device '%s' not found", device);
            return NULL;
        }
    }

    if (!is_pluggable_state(bs)) {
        error_setg(errp, "Device '%s' is not pluggable", device);
        return NULL;
    }

    return bs;
}

static void get_plugin_counters_cb(const char *counters, void *opaque)
{
    const char **result = opaque;
    *result = strdup(counters);
}

static NbsDriveInfo *get_drive_info(BlockDriverState *bs)
{
    assert(bs);

    BDRVPluggableState *s = bs->opaque;

    NbsDriveInfo *info = g_new0(NbsDriveInfo, 1);
    info->volume_id = g_strdup(s->impl_volume);
    info->node_name = g_strndup(bs->node_name, sizeof(bs->node_name));

    return info;
}

NbsDriveInfo *qmp_query_nbs_drive(const char *device, Error **errp)
{
    BlockDriverState *bs = get_pluggable_state(device, errp);
    if (!bs) {
        return NULL;
    }

    return get_drive_info(bs);
}

NbsDriveInfoList *qmp_query_nbs_drives(Error **errp)
{
    NbsDriveInfoList *head = NULL;
    NbsDriveInfoList **p_next = &head;
    BdrvNextIterator it;
    for (BlockDriverState *bs = bdrv_first(&it); bs; bs = bdrv_next(&it)) {
        if (!is_pluggable_state(bs)) {
            continue;
        }

        NbsDriveInfoList *info = g_new0(NbsDriveInfoList, 1);
        info->value = get_drive_info(bs);
        assert(info->value);

        *p_next = info;
        p_next = &info->next;
    }

    return head;
}

NbsClientCounters *qmp_query_nbs_client_counters(Error **errp)
{
    BdrvNextIterator it;
    /* Any NBS drive will do, so just find the first one */
    for (BlockDriverState *bs = bdrv_first(&it); bs; bs = bdrv_next(&it)) {
        if (!is_pluggable_state(bs)) {
            continue;
        }

        BDRVPluggableState *s = BS_TO_PLUGGABLE_STATE(bs);
        NbsClientCounters *res = g_new0(NbsClientCounters, 1);

        int err = s->plugin->get_dynamic_counters(
                s->plugin,
                get_plugin_counters_cb,
                &res->counters);

        /*
         * bdrv_next refs current bs and unrefs previous bs. So if we break the
         * loop we have to unref current bs ourselves
         */
        bdrv_next_cleanup(&it);
        if (err != BLOCK_PLUGIN_E_OK) {
            error_setg(errp, "Failed to get NBS client counters: %d", err);
            g_free(res);
            return NULL;
        }

        return res;
    }

    /*
     * Return empty counters set instead of an error
     * if there are no nbs drives
     */
    return g_new0(NbsClientCounters, 1);
}

void qmp_start_pluggable_trace(const char *device, uint32_t latency,
                               Error **errp)
{
    BlockDriverState *bs = get_pluggable_state(device, errp);
    if (bs) {
        block_trace_start(&BS_TO_PLUGGABLE_STATE(bs)->trace_state, latency,
                          errp);
    }
}

BlockTraceInfoList *qmp_stop_pluggable_trace(const char *device, Error **errp)
{
    BlockDriverState *bs = get_pluggable_state(device, errp);
    return bs ?
        block_trace_stop(&BS_TO_PLUGGABLE_STATE(bs)->trace_state, errp) : NULL;
}

void qmp_set_nbs_fail_writes(const char *device, bool enable, Error **errp)
{
    BlockDriverState *bs = get_pluggable_state(device, errp);
    if (bs) {
        BS_TO_PLUGGABLE_STATE(bs)->fail_writes = enable;
    }
}

void qmp_set_nbs_fail_reads(const char *device, bool enable, Error **errp)
{
    BlockDriverState *bs = get_pluggable_state(device, errp);
    if (bs) {
        BS_TO_PLUGGABLE_STATE(bs)->fail_reads = enable;
    }
}

/*
 * How NBS live migration works
 *
 * We want to prevent RW mounting of the same NBS volume on the several hosts
 * during migration. Therefore, when the target QEMU starts, it must perform
 * a read-only mount on all NBS volumes until the migration is complete.
 *
 * QEMU already has a mechanism to let block drivers support such use case.
 * There is a open_flag BDRV_O_INACTIVE. When this flag is set, it means that
 * block driver is inactive (not writeable).
 * If QEMU process has an '-incoming' option then all bdrv_open (before
 * migration completion) is called with BDRV_O_INACTIVE flag set.
 * Also there are two callbacks: bdrv_inactivate and bdrv_co_invalidate_cache.
 * These callback work in pairs:
 * - bdrv_inactivate is called only for active driver (BDRV_O_INACTIVE not set)
 * - bdrv_co_invalidate_cache is called only for inactive driver (BDRV_O_INACTIVE set)
 *
 * Workflow:
 *              source                         |             target
 * process starts                              |
 * unset BDRV_O_INACTIVE                       |
 * bdrv_open()                                 |
 *  -> nbs_mount(read-write)                   |
 * vm_start()                                  |
 *                                   user starts migration
 *                                             |
 *                                             | process starts
 *                                             | set BDRV_O_INACTIVE
 *                                             | bdrv_open()
 *                                             |  -> nbs_mount(read-only)
 *                                             | qmp migrate incoming
 * qmp migrate                                 |
 *                                  ... live migration ...
 * vm_stop()                                   |
 * set BDRV_O_INACTIVE                         |
 * bdrv_inactivate()                           |
 *  -> nbs_remount(read-only)                  |
 * complete migration (send device state, etc) |
 *                                             | unset BDRV_O_INACTIVE
 *                                             | bdrv_invalidate_cache
 *                                             |  -> nbs_remount(read-write)
 * process dies                                | vm_start()
 */

static void remount_volume(BDRVPluggableState *s,
                           enum BlockPlugin_AccessMode access_mode,
                           enum BlockPlugin_MountMode mount_mode,
                           Error **errp)
{
    struct BlockPlugin_MountOpts opts = {
        .volume_name = s->impl_volume,
        .mount_token = s->mount_token,
        .instance_id = qemu_get_vm_name(),
        .access_mode = access_mode,
        .mount_mode  = mount_mode,
    };

    uint64_t old_blocks_count = s->volume.blocks_count;
    uint32_t old_block_size = s->volume.block_size;

    int ret = s->plugin->mount_sync(s->plugin, &opts, &s->volume);
    if (ret != BLOCK_PLUGIN_E_OK) {
        error_setg(errp, "Failed to remount volume %s, error: %d",
                   s->impl_volume, ret);
        return;
    }

    /* Resizing is not supported now */
    g_assert(old_block_size == s->volume.block_size);
    if (old_blocks_count != s->volume.blocks_count) {
        warn_report("Volume blocks count has changed! "
                    "Old %" PRIu64 " != New %" PRIu64,
                    old_blocks_count, s->volume.blocks_count);
    }
}

static void coroutine_fn pluggable_co_invalidate_cache(BlockDriverState *bs,
                                                       Error **errp)
{
    BDRVPluggableState *s = BS_TO_PLUGGABLE_STATE(bs);
    remount_volume(s, BLOCK_PLUGIN_ACCESS_READ_WRITE, BLOCK_PLUGIN_MOUNT_LOCAL,
                   errp);
}

static int pluggable_inactivate(BlockDriverState *bs)
{
    BDRVPluggableState *s = BS_TO_PLUGGABLE_STATE(bs);
    Error *local_error = NULL;

    remount_volume(s, BLOCK_PLUGIN_ACCESS_READ_ONLY, BLOCK_PLUGIN_MOUNT_REMOTE,
                   &local_error);

    if (local_error) {
        error_report_err(local_error);
        return -EPERM;
    }
    return 0;
}

static BlockDriver bdrv_pluggable = {
    .format_name          = "pluggable",
    .instance_size        = sizeof(BDRVPluggableState),

    .bdrv_open            = pluggable_open,
    .bdrv_close           = pluggable_close,

    .bdrv_child_perm        = bdrv_filter_default_perms,
    .bdrv_co_readv          = pluggable_co_readv,
    .bdrv_co_writev         = pluggable_co_writev,
    .bdrv_co_pwrite_zeroes  = pluggable_co_pwrite_zeroes,

    .bdrv_refresh_limits      = pluggable_refresh_limits,
    .bdrv_probe_blocksizes    = pluggable_probe_blocksizes,
    .bdrv_probe_geometry      = pluggable_probe_geometry,

    .bdrv_attach_aio_context  = pluggable_attach_aio_context,
    .bdrv_detach_aio_context  = pluggable_detach_aio_context,

    .bdrv_inactivate          = pluggable_inactivate,
    .bdrv_co_invalidate_cache = pluggable_co_invalidate_cache,

    .create_opts          = &pluggable_opts,
};

static void bdrv_pluggable_init(void)
{
    bdrv_register(&bdrv_pluggable);
}

block_init(bdrv_pluggable_init);
