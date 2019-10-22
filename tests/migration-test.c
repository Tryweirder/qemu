/*
 * QTest testcase for migration
 *
 * Copyright (c) 2016-2018 Red Hat, Inc. and/or its affiliates
 *   based on the vhost-user-test.c that is:
 *      Copyright (c) 2014 Virtual Open Systems Sarl.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"

#include "libqtest.h"
#include "qapi/qmp/qdict.h"
#include "qemu/option.h"
#include "qemu/range.h"
#include "qemu/sockets.h"
#include "chardev/char.h"
#include "sysemu/sysemu.h"
#include "hw/nvram/chrp_nvram.h"
#include "qemu/cutils.h"
#include "blockstore-mock.h"

#define MIN_NVRAM_SIZE 8192 /* from spapr_nvram.c */

const unsigned start_address = 1024 * 1024;
const unsigned end_address = 100 * 1024 * 1024;
bool got_stop;

#if defined(__linux__)
#include <sys/syscall.h>
#include <sys/vfs.h>
#endif

#if defined(__linux__) && defined(__NR_userfaultfd) && defined(CONFIG_EVENTFD)
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>

static bool ufd_version_check(void)
{
    struct uffdio_api api_struct;
    uint64_t ioctl_mask;

    int ufd = syscall(__NR_userfaultfd, O_CLOEXEC);

    if (ufd == -1) {
        g_test_message("Skipping test: userfaultfd not available");
        return false;
    }

    api_struct.api = UFFD_API;
    api_struct.features = 0;
    if (ioctl(ufd, UFFDIO_API, &api_struct)) {
        g_test_message("Skipping test: UFFDIO_API failed");
        return false;
    }

    ioctl_mask = (__u64)1 << _UFFDIO_REGISTER |
                 (__u64)1 << _UFFDIO_UNREGISTER;
    if ((api_struct.ioctls & ioctl_mask) != ioctl_mask) {
        g_test_message("Skipping test: Missing userfault feature");
        return false;
    }

    return true;
}

#else
static bool ufd_version_check(void)
{
    g_test_message("Skipping test: Userfault not available (builtdtime)");
    return false;
}

#endif

static const char *tmpfs;

/* A simple PC boot sector that modifies memory (1-100MB) quickly
 * outputting a 'B' every so often if it's still running.
 */
#include "tests/migration/x86-a-b-bootblock.h"

static void init_bootfile_x86(const char *bootpath)
{
    FILE *bootfile = fopen(bootpath, "wb");

    g_assert_cmpint(fwrite(x86_bootsect, 512, 1, bootfile), ==, 1);
    fclose(bootfile);
}

static void init_bootfile_ppc(const char *bootpath)
{
    FILE *bootfile;
    char buf[MIN_NVRAM_SIZE];
    ChrpNvramPartHdr *header = (ChrpNvramPartHdr *)buf;

    memset(buf, 0, MIN_NVRAM_SIZE);

    /* Create a "common" partition in nvram to store boot-command property */

    header->signature = CHRP_NVPART_SYSTEM;
    memcpy(header->name, "common", 6);
    chrp_nvram_finish_partition(header, MIN_NVRAM_SIZE);

    /* FW_MAX_SIZE is 4MB, but slof.bin is only 900KB,
     * so let's modify memory between 1MB and 100MB
     * to do like PC bootsector
     */

    sprintf(buf + 16,
            "boot-command=hex .\" _\" begin %x %x do i c@ 1 + i c! 1000 +loop "
            ".\" B\" 0 until", end_address, start_address);

    /* Write partition to the NVRAM file */

    bootfile = fopen(bootpath, "wb");
    g_assert_cmpint(fwrite(buf, MIN_NVRAM_SIZE, 1, bootfile), ==, 1);
    fclose(bootfile);
}

/*
 * Wait for some output in the serial output file,
 * we get an 'A' followed by an endless string of 'B's
 * but on the destination we won't have the A.
 */
static void wait_for_serial(const char *side)
{
    char *serialpath = g_strdup_printf("%s/%s", tmpfs, side);
    FILE *serialfile = fopen(serialpath, "r");
    const char *arch = qtest_get_arch();
    int started = (strcmp(side, "src_serial") == 0 &&
                   strcmp(arch, "ppc64") == 0) ? 0 : 1;

    g_free(serialpath);
    do {
        int readvalue = fgetc(serialfile);

        if (!started) {
            /* SLOF prints its banner before starting test,
             * to ignore it, mark the start of the test with '_',
             * ignore all characters until this marker
             */
            switch (readvalue) {
            case '_':
                started = 1;
                break;
            case EOF:
                fseek(serialfile, 0, SEEK_SET);
                usleep(1000);
                break;
            }
            continue;
        }
        switch (readvalue) {
        case 'A':
            /* Fine */
            break;

        case 'B':
            /* It's alive! */
            fclose(serialfile);
            return;

        case EOF:
            started = (strcmp(side, "src_serial") == 0 &&
                       strcmp(arch, "ppc64") == 0) ? 0 : 1;
            fseek(serialfile, 0, SEEK_SET);
            usleep(1000);
            break;

        default:
            fprintf(stderr, "Unexpected %d on %s serial\n", readvalue, side);
            g_assert_not_reached();
        }
    } while (true);
}

/*
 * Events can get in the way of responses we are actually waiting for.
 */
static QDict *wait_command_fd(QTestState *who, int fd, const char *command)
{
    const char *event_string;
    QDict *response;

    if (fd != -1) {
        response = qtest_qmp_fds(who, &fd, 1, command);
    } else {
        response = qtest_qmp(who, command);
    }

    while (qdict_haskey(response, "event")) {
        /* OK, it was an event */
        event_string = qdict_get_str(response, "event");
        if (!strcmp(event_string, "STOP")) {
            got_stop = true;
        }
        QDECREF(response);
        response = qtest_qmp_receive(who);
    }
    return response;
}

static QDict *wait_command(QTestState *who, const char *command)
{
    return wait_command_fd(who, -1, command);
}

/*
 * It's tricky to use qemu's migration event capability with qtest,
 * events suddenly appearing confuse the qmp()/hmp() responses.
 */

static int64_t read_ram_property_int(QTestState *who, const char *property)
{
    QDict *rsp, *rsp_return, *rsp_ram;
    int64_t result;

    rsp = wait_command(who, "{ 'execute': 'query-migrate' }");
    rsp_return = qdict_get_qdict(rsp, "return");
    if (!qdict_haskey(rsp_return, "ram")) {
        /* Still in setup */
        result = 0;
    } else {
        rsp_ram = qdict_get_qdict(rsp_return, "ram");
        result = qdict_get_try_int(rsp_ram, property, 0);
    }
    QDECREF(rsp);
    return result;
}

static int64_t read_migrate_property_int(QTestState *who, const char *property)
{
    QDict *rsp, *rsp_return;
    int64_t result;

    rsp = wait_command(who, "{ 'execute': 'query-migrate' }");
    rsp_return = qdict_get_qdict(rsp, "return");
    result = qdict_get_try_int(rsp_return, property, 0);
    QDECREF(rsp);
    return result;
}

static uint64_t get_migration_pass(QTestState *who)
{
    return read_ram_property_int(who, "dirty-sync-count");
}

static bool check_migration_status(QTestState *who, const char *status)
{
    QDict *rsp, *rsp_return;
    bool got_status;
    const char *current_status;

    rsp = wait_command(who, "{ 'execute': 'query-migrate' }");
    rsp_return = qdict_get_qdict(rsp, "return");
    current_status = qdict_get_str(rsp_return, "status");
    got_status = strcmp(current_status, status) == 0;
    g_assert_cmpstr(current_status, !=,  "failed");
    QDECREF(rsp);
    return got_status;
}

static void wait_for_migration_status(QTestState *who, const char *goal)
{
    while (!check_migration_status(who, goal)) {
        usleep(1000);
    }
}

static void wait_for_migration_complete(QTestState *who)
{
    while (!check_migration_status(who, "completed")) {
        usleep(1000);
    }
}

static void wait_for_migration_pass(QTestState *who)
{
    uint64_t initial_pass = get_migration_pass(who);
    uint64_t pass;

    /* Wait for the 1st sync */
    while (!got_stop && !initial_pass) {
        usleep(1000);
        initial_pass = get_migration_pass(who);
    }

    do {
        usleep(1000);
        pass = get_migration_pass(who);
    } while (pass == initial_pass && !got_stop);
}

static void check_guests_ram(QTestState *who)
{
    /* Our ASM test will have been incrementing one byte from each page from
     * 1MB to <100MB in order.
     * This gives us a constraint that any page's byte should be equal or less
     * than the previous pages byte (mod 256); and they should all be equal
     * except for one transition at the point where we meet the incrementer.
     * (We're running this with the guest stopped).
     */
    unsigned address;
    uint8_t first_byte;
    uint8_t last_byte;
    bool hit_edge = false;
    bool bad = false;

    qtest_memread(who, start_address, &first_byte, 1);
    last_byte = first_byte;

    for (address = start_address + 4096; address < end_address; address += 4096)
    {
        uint8_t b;
        qtest_memread(who, address, &b, 1);
        if (b != last_byte) {
            if (((b + 1) % 256) == last_byte && !hit_edge) {
                /* This is OK, the guest stopped at the point of
                 * incrementing the previous page but didn't get
                 * to us yet.
                 */
                hit_edge = true;
            } else {
                fprintf(stderr, "Memory content inconsistency at %x"
                                " first_byte = %x last_byte = %x current = %x"
                                " hit_edge = %x\n",
                                address, first_byte, last_byte, b, hit_edge);
                bad = true;
            }
        }
        last_byte = b;
    }
    g_assert_false(bad);
}

static void cleanup(const char *filename)
{
    char *path = g_strdup_printf("%s/%s", tmpfs, filename);

    unlink(path);
    g_free(path);
}

static char *get_shmem_opts(const char *mem_size, const char *shmem_path)
{
    return g_strdup_printf("-object memory-backend-file,id=mem0,size=%s"
                           ",mem-path=%s,share=on -numa node,memdev=mem0",
                           mem_size, shmem_path);
}

static void migrate_check_parameter(QTestState *who, const char *parameter,
                                    const char *value)
{
    QDict *rsp, *rsp_return;
    char *result;

    rsp = wait_command(who, "{ 'execute': 'query-migrate-parameters' }");
    rsp_return = qdict_get_qdict(rsp, "return");
    result = g_strdup_printf("%" PRId64,
                             qdict_get_try_int(rsp_return,  parameter, -1));
    g_assert_cmpstr(result, ==, value);
    g_free(result);
    QDECREF(rsp);
}

static void migrate_set_parameter(QTestState *who, const char *parameter,
                                  const char *value)
{
    QDict *rsp;
    gchar *cmd;

    cmd = g_strdup_printf("{ 'execute': 'migrate-set-parameters',"
                          "'arguments': { '%s': %s } }",
                          parameter, value);
    rsp = qtest_qmp(who, cmd);
    g_free(cmd);
    g_assert(qdict_haskey(rsp, "return"));
    QDECREF(rsp);
    migrate_check_parameter(who, parameter, value);
}

static bool migrate_get_parameter_bool(QTestState *who, const char *parameter)
{
    QDict *rsp;
    bool result;

    rsp = wait_command(who, "{ 'execute': 'query-migrate-parameters' }");
    result = qdict_get_bool(qdict_get_qdict(rsp, "return"), parameter);
    QDECREF(rsp);
    return result;
}

static void migrate_check_parameter_bool(QTestState *who, const char *parameter,
                                         bool value)
{
    bool result;

    result = migrate_get_parameter_bool(who, parameter);
    g_assert_true(result == value);
}

static void migrate_set_parameter_bool(QTestState *who, const char *parameter,
                                       bool value)
{
    QDict *rsp;

    rsp = qtest_qmp(who,
                    "{ 'execute': 'migrate-set-parameters',"
                    "'arguments': { %s: %i } }",
                    parameter, value);
    g_assert(qdict_haskey(rsp, "return"));
    QDECREF(rsp);
    migrate_check_parameter_bool(who, parameter, value);
}

static void migrate_set_capability(QTestState *who, const char *capability,
                                   const char *value)
{
    QDict *rsp;
    gchar *cmd;

    cmd = g_strdup_printf("{ 'execute': 'migrate-set-capabilities',"
                          "'arguments': { "
                          "'capabilities': [ { "
                          "'capability': '%s', 'state': %s } ] } }",
                          capability, value);
    rsp = qtest_qmp(who, cmd);
    g_free(cmd);
    g_assert(qdict_haskey(rsp, "return"));
    QDECREF(rsp);
}

static void migrate(QTestState *who, const char *uri)
{
    QDict *rsp;
    gchar *cmd;

    cmd = g_strdup_printf("{ 'execute': 'migrate',"
                          "'arguments': { 'uri': '%s' } }",
                          uri);
    rsp = wait_command(who, cmd);
    g_free(cmd);
    g_assert(qdict_haskey(rsp, "return"));
    QDECREF(rsp);
}

static void migrate_start_postcopy(QTestState *who)
{
    QDict *rsp;

    rsp = wait_command(who, "{ 'execute': 'migrate-start-postcopy' }");
    g_assert(qdict_haskey(rsp, "return"));
    QDECREF(rsp);
}

static int test_migrate_start(QTestState **from, QTestState **to,
                               const char *uri, bool hide_stderr,
                               bool use_shmem, const char *opts_src,
                               const char *opts_dst)
{
    gchar *cmd_src, *cmd_dst;
    char *bootpath = NULL;
    char *extra_opts = NULL;
    char *shmem_path = NULL;
    const char *arch = qtest_get_arch();
    const char *accel = "kvm:tcg";

    opts_src = opts_src ? opts_src : "";
    opts_dst = opts_dst ? opts_dst : "";

    if (use_shmem) {
        if (!g_file_test("/dev/shm", G_FILE_TEST_IS_DIR)) {
            g_test_skip("/dev/shm is not supported");
            return -1;
        }
        shmem_path = g_strdup_printf("/dev/shm/qemu-%d", getpid());
    }

    got_stop = false;
    bootpath = g_strdup_printf("%s/bootsect", tmpfs);
    if (strcmp(arch, "i386") == 0 || strcmp(arch, "x86_64") == 0) {
        init_bootfile_x86(bootpath);
        extra_opts = use_shmem ? get_shmem_opts("150M", shmem_path) : NULL;
        cmd_src = g_strdup_printf("-machine accel=%s -m 150M"
                                  " -name source,debug-threads=on"
                                  " -serial file:%s/src_serial"
                                  " -drive file=%s,format=raw,if=floppy %s %s",
                                  accel, tmpfs, bootpath,
                                  extra_opts ? extra_opts : "", opts_src);
        cmd_dst = g_strdup_printf("-machine accel=%s -m 150M"
                                  " -name target,debug-threads=on"
                                  " -serial file:%s/dest_serial"
                                  " -drive file=%s,format=raw,if=floppy"
                                  " -incoming %s %s %s",
                                  accel, tmpfs, bootpath, uri,
                                  extra_opts ? extra_opts : "", opts_dst);
    } else if (strcmp(arch, "ppc64") == 0) {

        /* On ppc64, the test only works with kvm-hv, but not with kvm-pr */
        if (access("/sys/module/kvm_hv", F_OK)) {
            accel = "tcg";
        }
        init_bootfile_ppc(bootpath);
        extra_opts = use_shmem ? get_shmem_opts("256M", shmem_path) : NULL;
        cmd_src = g_strdup_printf("-machine accel=%s -m 256M"
                                  " -name source,debug-threads=on"
                                  " -serial file:%s/src_serial"
                                  " -drive file=%s,if=pflash,format=raw %s %s",
                                  accel, tmpfs, bootpath,
                                  extra_opts ? extra_opts : "", opts_src);
        cmd_dst = g_strdup_printf("-machine accel=%s -m 256M"
                                  " -name target,debug-threads=on"
                                  " -serial file:%s/dest_serial"
                                  " -incoming %s %s %s",
                                  accel, tmpfs, uri,
                                  extra_opts ? extra_opts : "", opts_dst);
    } else {
        g_assert_not_reached();
    }

    g_free(bootpath);
    g_free(extra_opts);

    if (hide_stderr) {
        gchar *tmp;
        tmp = g_strdup_printf("%s 2>/dev/null", cmd_src);
        g_free(cmd_src);
        cmd_src = tmp;

        tmp = g_strdup_printf("%s 2>/dev/null", cmd_dst);
        g_free(cmd_dst);
        cmd_dst = tmp;
    }

    *from = qtest_start(cmd_src);
    g_free(cmd_src);

    *to = qtest_init(cmd_dst);
    g_free(cmd_dst);

    /*
     * Remove shmem file immediately to avoid memory leak in test failed case.
     * It's valid becase QEMU has already opened this file
     */
    if (use_shmem) {
        unlink(shmem_path);
        g_free(shmem_path);
    }

    return 0;
}

static void test_migrate_end(QTestState *from, QTestState *to, bool test_dest)
{
    unsigned char dest_byte_a, dest_byte_b, dest_byte_c, dest_byte_d;

    qtest_quit(from);

    if (test_dest) {
        qtest_memread(to, start_address, &dest_byte_a, 1);

        /* Destination still running, wait for a byte to change */
        do {
            qtest_memread(to, start_address, &dest_byte_b, 1);
            usleep(1000 * 10);
        } while (dest_byte_a == dest_byte_b);

        qtest_qmp_discard_response(to, "{ 'execute' : 'stop'}");

        /* With it stopped, check nothing changes */
        qtest_memread(to, start_address, &dest_byte_c, 1);
        usleep(1000 * 200);
        qtest_memread(to, start_address, &dest_byte_d, 1);
        g_assert_cmpint(dest_byte_c, ==, dest_byte_d);

        check_guests_ram(to);
    }

    qtest_quit(to);

    cleanup("bootsect");
    cleanup("migsocket");
    cleanup("src_serial");
    cleanup("dest_serial");
}

static void deprecated_set_downtime(QTestState *who, const double value)
{
    QDict *rsp;
    gchar *cmd;
    char *expected;
    int64_t result_int;

    cmd = g_strdup_printf("{ 'execute': 'migrate_set_downtime',"
                          "'arguments': { 'value': %g } }", value);
    rsp = qtest_qmp(who, cmd);
    g_free(cmd);
    g_assert(qdict_haskey(rsp, "return"));
    QDECREF(rsp);
    result_int = value * 1000L;
    expected = g_strdup_printf("%" PRId64, result_int);
    migrate_check_parameter(who, "downtime-limit", expected);
    g_free(expected);
}

static void deprecated_set_speed(QTestState *who, const char *value)
{
    QDict *rsp;
    gchar *cmd;

    cmd = g_strdup_printf("{ 'execute': 'migrate_set_speed',"
                          "'arguments': { 'value': %s } }", value);
    rsp = qtest_qmp(who, cmd);
    g_free(cmd);
    g_assert(qdict_haskey(rsp, "return"));
    QDECREF(rsp);
    migrate_check_parameter(who, "max-bandwidth", value);
}

static void test_deprecated(void)
{
    QTestState *from;

    from = qtest_start("");

    deprecated_set_downtime(from, 0.12345);
    deprecated_set_speed(from, "12345");

    qtest_quit(from);
}

static void test_migrate(void)
{
    char *uri = g_strdup_printf("unix:%s/migsocket", tmpfs);
    QTestState *from, *to;

    if (test_migrate_start(&from, &to, uri, false, false, NULL, NULL)) {
        return;
    }

    migrate_set_capability(from, "postcopy-ram", "true");
    migrate_set_capability(to, "postcopy-ram", "true");

    /* We want to pick a speed slow enough that the test completes
     * quickly, but that it doesn't complete precopy even on a slow
     * machine, so also set the downtime.
     */
    migrate_set_parameter(from, "max-bandwidth", "100000000");
    migrate_set_parameter(from, "downtime-limit", "1");

    /* Wait for the first serial output from the source */
    wait_for_serial("src_serial");

    migrate(from, uri);

    wait_for_migration_pass(from);

    migrate_start_postcopy(from);

    if (!got_stop) {
        qtest_qmp_eventwait(from, "STOP");
    }

    qtest_qmp_eventwait(to, "RESUME");

    wait_for_serial("dest_serial");
    wait_for_migration_complete(from);

    g_free(uri);

    test_migrate_end(from, to, true);
}

static void wait_for_migration_fail(QTestState *from, bool allow_active)
{
    QDict *rsp, *rsp_return;
    const char *status;
    bool failed;

    do {
        rsp = wait_command(from, "{ 'execute': 'query-migrate' }");
        rsp_return = qdict_get_qdict(rsp, "return");

        status = qdict_get_str(rsp_return, "status");

        g_assert(!strcmp(status, "setup") || !(strcmp(status, "failed")) ||
                 (allow_active && !strcmp(status, "active")));
        failed = !strcmp(status, "failed");
        QDECREF(rsp);
    } while (!failed);

    /* Is the machine currently running? */
    rsp = wait_command(from, "{ 'execute': 'query-status' }");
    g_assert(qdict_haskey(rsp, "return"));
    rsp_return = qdict_get_qdict(rsp, "return");
    g_assert(qdict_haskey(rsp_return, "running"));
    g_assert(qdict_get_bool(rsp_return, "running"));
    QDECREF(rsp);
}

static void test_baddest(void)
{
    QTestState *from, *to;

    if (test_migrate_start(&from, &to, "tcp:0:0", true, false, NULL, NULL)) {
        return;
    }
    migrate(from, "tcp:0:0");
    wait_for_migration_fail(from, false);
    test_migrate_end(from, to, false);
}

static void test_ignore_shared(void)
{
    char *uri = g_strdup_printf("unix:%s/migsocket", tmpfs);
    QTestState *from, *to;

    if (test_migrate_start(&from, &to, uri, false, true, NULL, NULL)) {
        return;
    }

    migrate_set_capability(from, "x-ignore-shared", "true");
    migrate_set_capability(to, "x-ignore-shared", "true");

    /* Wait for the first serial output from the source */
    wait_for_serial("src_serial");

    migrate(from, uri);

    wait_for_migration_pass(from);

    if (!got_stop) {
        qtest_qmp_eventwait(from, "STOP");
    }

    qtest_qmp_eventwait(to, "RESUME");

    wait_for_serial("dest_serial");
    wait_for_migration_complete(from);

    /* Check whether shared RAM has been really skipped */
    g_assert_cmpint(read_ram_property_int(from, "transferred"), <, 1024 * 1024);

    test_migrate_end(from, to, true);
    g_free(uri);
}

static void qmp_cmd_checked(QTestState *state, QDict **result, int fd,
                            const char *fmt, ...)
{
    QDict *response;
    gchar *cmd;

    va_list ap;
    va_start(ap, fmt);
    cmd = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    if (fd != -1) {
        response = wait_command_fd(state, fd, cmd);
    } else {
        response = wait_command(state, cmd);
    }
    g_assert_nonnull(response);
    if (qdict_haskey(response, "error")) {
        QDict *error = qobject_to(QDict, qdict_get(response, "error"));
        fprintf(stderr, "Command %s failed: %s\n", cmd,
                qdict_get_str(error, "desc"));
        g_assert_false(qdict_haskey(response, "error"));
    }
    if (result) {
        *result = qdict_get_qdict(response, "return");
        g_assert_nonnull(*result);
        QINCREF(*result);
    }
    QDECREF(response);
}

static void plug_blockdev(QTestState *state, const char *file_path,
                          const char *bus_name, const char *node_name)
{
    QDict *resp;

    qmp_cmd_checked(
        state, NULL, -1,
        "{'execute': 'object-add', 'arguments': {"
        " 'id': 'iot-%s',"
        " 'qom-type': 'iothread' }}",
        node_name);

    qmp_cmd_checked(
        state, NULL, -1,
        "{'execute': 'blockdev-add', 'arguments': {"
        " 'driver': 'pluggable', "
        " 'node-name': 'node-%s',"
        " 'impl_volume': '%s',"
        " 'impl_path': 'tests/libblockstore-mock.so',"
        " 'cache': {'direct':true},"
        " 'async': true,"
        " 'detect-zeroes': 'on' }}",
        node_name, file_path);

    resp = qtest_qmp_eventwait_ref(state, "BLOCKDEV_ADDED");
    g_assert_false(qdict_haskey(qdict_get_qdict(resp, "data"), "error"));
    QDECREF(resp);

    qmp_cmd_checked(
        state, NULL, -1,
        "{'execute': 'device_add', 'arguments': {"
        " 'driver': 'virtio-blk-pci',"
        " 'drive': 'node-%s',"
        " 'id': 'driveid-%s',"
        " 'write-cache': 'off',"
        " 'rerror': 'report',"
        " 'werror': 'report',"
        " 'bus': '%s' }}",
        node_name, node_name, bus_name);
}

static void plug_netdev(QTestState *state, const char *bus_name, const char *id)
{
    qmp_cmd_checked(
        state, NULL, -1,
        "{'execute': 'netdev_add', 'arguments': {"
        " 'id': 'netdev-%s',"
        " 'type': 'user' }}",
        id);
    qmp_cmd_checked(
        state, NULL, -1,
        "{'execute': 'device_add', 'arguments': {"
        " 'driver': 'virtio-net-pci',"
        " 'bus': '%s',"
        " 'disable-legacy': 'off',"
        " 'mq': 'on',"
        " 'id': 'net-%s',"
        " 'netdev': 'netdev-%s' }}",
        bus_name, id, id);
}

static void init_image_file(const char *path, size_t size)
{
    FILE *f;
    void *buf = g_malloc0(size);
    size_t written;

    f = fopen(path, "wb");
    g_assert_nonnull(f);

    written = fwrite(buf, 1, size, f);
    g_assert_cmpint(written, ==, size);

    g_free(buf);
    fclose(f);
}

/* Test migration with close to prod configuration */
static void test_yc_migration(const char *cpu, bool zeropage_scan)
{
    char *uri = g_strdup_printf("unix:%s/migsocket", tmpfs);
    QTestState *from, *to;
    gchar *shmem_path, *bootpath, *image1_path, *image2_path;
    gchar *cmd_src, *cmd_dst;
    gchar *mem_opts;
    const char *opts_format;
    QDict *rsp;

    if (strcmp(qtest_get_arch(), "x86_64")) {
        g_test_skip("This test requires x86_64 arch");
        return;
    }

    if (!g_file_test("/dev/shm", G_FILE_TEST_IS_DIR)) {
        g_test_skip("/dev/shm is not supported");
        return;
    }

    opts_format =
        "-name %s,debug-threads=on"
        " -cpu %s"
        " -m 110M" /* The loader touches only 100M, but we need 90%
                    * to be touched for zeropage-scan */
        " %s" /* Memory opts */
        " -numa node,memdev=mem0"
        " -machine q35,sata=false,usb=off,accel=kvm"
        " -vga std"
        " -device usb-ehci"
        " -device usb-tablet"
        " -device pxb-pcie,bus_nr=128,bus=pcie.0,id=pcie.1,numa_node=0"
        " -device pcie-root-port,id=s0,slot=0,bus=pcie.1"
        " -device pcie-root-port,id=s1,slot=1,bus=pcie.1"
        " -device pcie-root-port,id=s2,slot=2,bus=pcie.1"
        " -device pcie-root-port,id=s3,slot=3,bus=pcie.1"
        " -device pcie-root-port,id=s4,slot=4,bus=pcie.1"
        " -device pcie-root-port,id=s5,slot=5,bus=pcie.1"
        " -device pcie-root-port,id=s6,slot=6,bus=pcie.1"
        " -device pcie-root-port,id=s7,slot=7,bus=pcie.1"
        " -device pxb-pcie,bus_nr=137,bus=pcie.0,id=pcie.2,numa_node=0"
        " -device pcie-root-port,id=s8,slot=8,bus=pcie.2"
        " -device pcie-root-port,id=s9,slot=9,bus=pcie.2"
        " -device pcie-root-port,id=s10,slot=10,bus=pcie.2"
        " -device pcie-root-port,id=s11,slot=11,bus=pcie.2"
        " -device pcie-root-port,id=s12,slot=12,bus=pcie.2"
        " -device pcie-root-port,id=s13,slot=13,bus=pcie.2"
        " -device pcie-root-port,id=s14,slot=14,bus=pcie.2"
        " -device pcie-root-port,id=s15,slot=15,bus=pcie.2"
        " -serial file:%s/%s"
        " -drive file=%s,format=raw,if=floppy"
        " -S %s";

    bootpath = g_strdup_printf("%s/bootsect", tmpfs);
    image1_path = g_strdup_printf("%s/mock-image-1.img", tmpfs);
    image2_path = g_strdup_printf("%s/mock-image-2.img", tmpfs);

    init_bootfile_x86(bootpath);
    init_image_file(image1_path, MOCK_VOLUME_BLOCK_SIZE);
    init_image_file(image2_path, MOCK_VOLUME_BLOCK_SIZE);

    shmem_path = g_strdup_printf("/dev/shm/qemu-%d", getpid());
    mem_opts = g_strdup_printf(" -object memory-backend-file"
                               ",id=mem0,size=110M,mem-path=%s,share=on",
                               shmem_path);

    cmd_src = g_strdup_printf(opts_format, "source", cpu, mem_opts,
                              tmpfs, "src_serial",
                              bootpath, "");
    cmd_dst = g_strdup_printf(opts_format, "target", cpu, mem_opts,
                              tmpfs, "dest_serial",
                              bootpath, " -incoming defer");

    got_stop = false;
    from = qtest_start(cmd_src);
    g_free(cmd_src);

    to = qtest_init(cmd_dst);
    g_free(cmd_dst);

    g_free(mem_opts);

    /*
     * Remove shmem file immediately to avoid memory leak in test failed case.
     * It's valid because QEMU has already opened this file
     */
    unlink(shmem_path);
    g_free(shmem_path);

    /* Hotplug some devs to source */
    plug_blockdev(from, image1_path, "s0", "mock-drive-1");
    plug_netdev(from, "s8", "0");
    qmp_cmd_checked(from, NULL, -1, "{'execute': 'system_reset'}");
    qtest_qmp_eventwait(from, "RESET");

    /* Hotplug some devs to target */
    plug_blockdev(to, image1_path, "s0", "mock-drive-1");
    plug_netdev(to, "s8", "0");
    /* These devs will be plugged below, after BIOS initalization */
    plug_blockdev(to, image2_path, "s1", "mock-drive-2");
    plug_netdev(to, "s9", "1");
    qmp_cmd_checked(to, NULL, -1, "{'execute': 'system_reset'}");
    qtest_qmp_eventwait(to, "RESET");

    /* Start source VM and wait for the first serial output from the source */
    qmp_cmd_checked(from, NULL, -1, "{'execute': 'cont'}");
    wait_for_serial("src_serial");

    /*
     * Plug in some mock devs after BIOS initalization when our test is running.
     * So we are sure that these devices will stay uninitalized by guest.
     */
    plug_blockdev(from, image2_path, "s1", "mock-drive-2");
    plug_netdev(from, "s9", "1");

    migrate_set_capability(from, "x-ignore-shared", "true");
    migrate_set_capability(to, "x-ignore-shared", "true");

    /* Test zeropage-scan on source */
    qmp_cmd_checked(from, &rsp, -1, "{'execute': 'query-zeropage-scan'}");
    g_assert_true(qdict_get_bool(rsp, "enabled") == zeropage_scan);
    if (zeropage_scan) {
        /* Wait for zeropage scan's discard */
        while (qdict_get_int(rsp, "discarded_size") < 0) {
            g_usleep(G_USEC_PER_SEC / 10); /* 100ms */
            QDECREF(rsp);
            qmp_cmd_checked(from, &rsp, -1,
                            "{'execute': 'query-zeropage-scan'}");
        }
    }
    QDECREF(rsp);

    /* Start migration */
    qmp_cmd_checked(to, NULL, -1,
                    "{'execute': 'migrate-incoming', 'arguments': {"
                    " 'uri': '%s' }}", uri);
    migrate(from, uri);
    wait_for_migration_pass(from);

    if (!got_stop) {
        qtest_qmp_eventwait(from, "STOP");
    }

    wait_for_migration_complete(from);

    /* Test zeropage-scan on target */
    qmp_cmd_checked(to, &rsp, -1, "{'execute': 'query-zeropage-scan'}");
    g_assert_true(qdict_get_bool(rsp, "enabled") == zeropage_scan);
    if (zeropage_scan) {
        /* Discarded size must be transferred */
        g_assert_cmpint(qdict_get_int(rsp, "discarded_size"), >=, 0);
    }
    QDECREF(rsp);

    /* Resume target */
    qmp_cmd_checked(to, NULL, -1, "{'execute': 'cont'}");
    wait_for_serial("dest_serial");

    test_migrate_end(from, to, true);

    g_free(image1_path);
    g_free(image2_path);
    g_free(bootpath);
    g_free(uri);
}

#define YC_CPU_OPTIONS_GENERAL ",l3-cache=on,-vmx,+spec-ctrl,+ssbd"
#define YC_CPU_OPTIONS_WINDOWS ",hv_relaxed,hv_spinlocks=0x1fff,hv_vapic" \
                               ",hv_time,hv_crash,hv_reset,hv_vpindex"    \
                               ",hv_runtime,hv_synic,hv_stimer"

static void test_yc_migration_haswell(void)
{
    test_yc_migration("Haswell-noTSX" YC_CPU_OPTIONS_GENERAL, false);
}

static void test_yc_migration_cascadelake(void)
{
    test_yc_migration("Cascadelake-Server,+invtsc" YC_CPU_OPTIONS_GENERAL,
                      false);
}

static void test_yc_migration_haswell_win(void)
{
    test_yc_migration("Haswell-noTSX" YC_CPU_OPTIONS_GENERAL
                      YC_CPU_OPTIONS_WINDOWS, true);
}

static void test_yc_migration_cascadelake_win(void)
{
    test_yc_migration("Cascadelake-Server,+invtsc" YC_CPU_OPTIONS_GENERAL
                      YC_CPU_OPTIONS_WINDOWS, true);
}

static void test_migrate_fd_proto(void)
{
    QTestState *from, *to;
    int ret;
    int pair[2];
    QDict *rsp;
    const char *error_desc;

    if (test_migrate_start(&from, &to, "defer", false, false, NULL, NULL)) {
        return;
    }

    /*
     * We want to pick a speed slow enough that the test completes
     * quickly, but that it doesn't complete precopy even on a slow
     * machine, so also set the downtime.
     */
    /* 1 ms should make it not converge*/
    migrate_set_parameter(from, "downtime-limit", "1");
    /* 1GB/s */
    migrate_set_parameter(from, "max-bandwidth", "1000000000");

    /* Wait for the first serial output from the source */
    wait_for_serial("src_serial");

    /* Create two connected sockets for migration */
    ret = socketpair(PF_LOCAL, SOCK_STREAM, 0, pair);
    g_assert_cmpint(ret, ==, 0);

    /* Send the 1st socket to the target */
    rsp = wait_command_fd(to, pair[0],
                          "{ 'execute': 'getfd',"
                          "  'arguments': { 'fdname': 'fd-mig' }}");
    g_assert(qdict_haskey(rsp, "return"));
    QDECREF(rsp);
    close(pair[0]);

    /* Start incoming migration from the 1st socket */
    rsp = wait_command(to, "{ 'execute': 'migrate-incoming',"
                           "  'arguments': { 'uri': 'fd:fd-mig' }}");
    g_assert(qdict_haskey(rsp, "return"));
    QDECREF(rsp);

    /* Send the 2nd socket to the target */
    rsp = wait_command_fd(from, pair[1],
                          "{ 'execute': 'getfd',"
                          "  'arguments': { 'fdname': 'fd-mig' }}");
    g_assert(qdict_haskey(rsp, "return"));
    QDECREF(rsp);
    close(pair[1]);

    /* Start migration to the 2nd socket*/
    migrate(from, "fd:fd-mig");

    wait_for_migration_pass(from);

    /* 300ms should converge */
    migrate_set_parameter(from, "downtime-limit", "300");

    if (!got_stop) {
        qtest_qmp_eventwait(from, "STOP");
    }
    qtest_qmp_eventwait(to, "RESUME");

    /* Test closing fds */
    rsp = wait_command(from, "{ 'execute': 'closefd',"
                             "  'arguments': { 'fdname': 'fd-mig' }}");
    g_assert_true(qdict_haskey(rsp, "error"));
    error_desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
    g_assert_cmpstr(error_desc, ==, "File descriptor named 'fd-mig' not found");
    QDECREF(rsp);

    rsp = wait_command(to, "{ 'execute': 'closefd',"
                             "  'arguments': { 'fdname': 'fd-mig' }}");
    g_assert_true(qdict_haskey(rsp, "error"));
    error_desc = qdict_get_str(qdict_get_qdict(rsp, "error"), "desc");
    g_assert_cmpstr(error_desc, ==, "File descriptor named 'fd-mig' not found");
    QDECREF(rsp);

    /* Complete migration */
    wait_for_serial("dest_serial");
    wait_for_migration_complete(from);
    test_migrate_end(from, to, true);
}

static void do_test_validate_uuid(const char *uuid_arg_src,
                                  const char *uuid_arg_dst,
                                  bool should_fail,
                                  bool hide_stderr)
{
    char *uri = g_strdup_printf("unix:%s/migsocket", tmpfs);
    QTestState *from, *to;

    if (test_migrate_start(&from, &to, uri, hide_stderr, false,
                           uuid_arg_src, uuid_arg_dst)) {
        return;
    }

    migrate_set_capability(from, "x-validate-uuid", "true");
    migrate(from, uri);
    if (should_fail) {
        wait_for_migration_fail(from, true);
    } else {
        wait_for_migration_pass(from);
    }
    test_migrate_end(from, to, false);
    g_free(uri);
}

static void test_validate_uuid(void)
{
    do_test_validate_uuid("-uuid 11111111-1111-1111-1111-111111111111",
                          "-uuid 11111111-1111-1111-1111-111111111111",
                          false, false);
}

static void test_validate_uuid_error(void)
{
    do_test_validate_uuid("-uuid 11111111-1111-1111-1111-111111111111",
                          "-uuid 22222222-2222-2222-2222-222222222222",
                          true, true);
}

static void test_validate_uuid_src_not_set(void)
{
    do_test_validate_uuid(NULL, "-uuid 11111111-1111-1111-1111-111111111111",
                          false, true);
}

static void test_validate_uuid_dst_not_set(void)
{
    do_test_validate_uuid("-uuid 11111111-1111-1111-1111-111111111111", NULL,
                          false, true);
}

static void wait_for_throttle_event(QTestState *who, int percentage,
                                    bool expect_completion)
{
    QDict *response = NULL;
    const char *event;
    QDict *data;

    do {
        QDECREF(response);
        response = qtest_qmp_receive(who);
        g_assert_true(qdict_haskey(response, "event"));

        event = qdict_get_str(response, "event");
    } while (!strcmp(event, "MIGRATION_PASS"));

    data = qdict_get_qdict(response, "data");

    /* Migration may converge too early, it's ok in some cases */
    if (!strcmp(event, "MIGRATION")) {
        g_assert_cmpstr(qdict_get_str(data, "status"), ==, "completed");
        g_assert_true(expect_completion);
    } else {
        g_assert_cmpstr(event, ==, "MIGRATION_THROTTLE");
        g_assert_cmpint(qdict_get_int(data, "percentage"), ==, percentage);
    }

    QDECREF(response);
}

static void do_test_migrate_auto_converge(int64_t init_pct, int64_t inc_pct,
                                          int64_t max_pct, bool force_stop)
{
    char *uri = g_strdup_printf("unix:%s/migsocket", tmpfs);
    QTestState *from, *to;
    char buf[50];
    int64_t remaining, percentage;

    /*
     * We want the test to be stable and as fast as possible.
     * E.g., with 1Gb/s bandwith migration may pass without throttling,
     * so we need to decrease a bandwidth.
     */
    const int64_t max_bandwidth = 200000000; /* ~200Mb/s */
    const int64_t downtime_limit = 20; /* 20ms */
    /*
     * We migrate through unix-socket (> 500Mb/s).
     * Thus, expected migration speed ~= bandwidth limit (< 500Mb/s).
     * So, we can predict expected_threshold
     */
    const int64_t expected_threshold = max_bandwidth * downtime_limit / 1000;

    if (test_migrate_start(&from, &to, uri, false, false, NULL, NULL)) {
        return;
    }

    migrate_set_capability(from, "auto-converge", "true");
    snprintf(buf, sizeof(buf), "%" PRId64, init_pct);
    migrate_set_parameter(from, "cpu-throttle-initial", buf);
    snprintf(buf, sizeof(buf), "%" PRId64, inc_pct);
    migrate_set_parameter(from, "cpu-throttle-increment", buf);
    snprintf(buf, sizeof(buf), "%" PRId64, max_pct);
    migrate_set_parameter(from, "max-cpu-throttle", buf);
    migrate_set_parameter_bool(from, "x-cpu-throttle-force-stop", force_stop);

    snprintf(buf, sizeof(buf), "%" PRId64, max_bandwidth);
    migrate_set_parameter(from, "max-bandwidth", buf);
    snprintf(buf, sizeof(buf), "%" PRId64, downtime_limit);
    migrate_set_parameter(from, "downtime-limit", buf);

    /* To check remaining size after precopy */
    migrate_set_capability(from, "pause-before-switchover", "true");
    /* To check intermediate percentage values */
    migrate_set_capability(from, "events", "true");

    /* Wait for the first serial output from the source */
    wait_for_serial("src_serial");

    migrate(from, uri);
    wait_for_migration_status(from, "active");

    /* Wait for all possible throttle percentages */
    wait_for_throttle_event(from, init_pct, false);
    wait_for_throttle_event(from, init_pct + inc_pct, false);
    if (force_stop) {
        wait_for_throttle_event(from, 100, false);
    } else {
        /* We assume that max_pct might not be reached and it's ok */
        wait_for_throttle_event(from, max_pct, true);
    }

    /*
     * Wait for pre-switchover status to check last throttle percentage
     * and remaining. These values will be zeroed later
     */
    wait_for_migration_status(from, "pre-switchover");

    /* We expect that migration can't converge without throttling */
    percentage = read_migrate_property_int(from, "cpu-throttle-percentage");
    /* The initial percentage should not be enough to converge */
    g_assert_cmpint(percentage, >, init_pct);
    g_assert_cmpint(percentage, <=, max_pct);

    remaining = read_ram_property_int(from, "remaining");
    if (force_stop) {
        g_assert_cmpint(remaining, >=, expected_threshold);
    } else {
        g_assert_cmpint(remaining, <, expected_threshold);
    }

    wait_command(from, "{ 'execute': 'migrate-continue',"
                       "  'arguments': { 'state': 'pre-switchover' }}");

    qtest_qmp_eventwait(to, "RESUME");

    wait_for_serial("dest_serial");
    wait_for_migration_complete(from);

    g_free(uri);

    test_migrate_end(from, to, true);
}

static void test_migrate_auto_converge(void)
{
    do_test_migrate_auto_converge(1, 51, 99, false);
}

static void test_migrate_auto_converge_force(void)
{
    do_test_migrate_auto_converge(1, 20, 30, true);
}

int main(int argc, char **argv)
{
    char template[] = "/tmp/migration-test-XXXXXX";
    int ret;

    g_test_init(&argc, &argv, NULL);

    if (!ufd_version_check()) {
        return 0;
    }

    tmpfs = mkdtemp(template);
    if (!tmpfs) {
        g_test_message("mkdtemp on path (%s): %s\n", template, strerror(errno));
    }
    g_assert(tmpfs);

    module_call_init(MODULE_INIT_QOM);

    qtest_add_func("/migration/postcopy/unix", test_migrate);
    qtest_add_func("/migration/deprecated", test_deprecated);
    qtest_add_func("/migration/bad_dest", test_baddest);
    qtest_add_func("/migration/ignore_shared", test_ignore_shared);
    qtest_add_func("/migration/yc_migration_haswell",
                   test_yc_migration_haswell);
    qtest_add_func("/migration/yc_migration_cascadelake",
                   test_yc_migration_cascadelake);
    qtest_add_func("/migration/yc_migration_haswell_win",
                   test_yc_migration_haswell_win);
    qtest_add_func("/migration/yc_migration_cascadelake_win",
                   test_yc_migration_cascadelake_win);
    qtest_add_func("/migration/fd_proto", test_migrate_fd_proto);
    qtest_add_func("/migration/validate_uuid", test_validate_uuid);
    qtest_add_func("/migration/validate_uuid_error", test_validate_uuid_error);
    qtest_add_func("/migration/validate_uuid_src_not_set",
                   test_validate_uuid_src_not_set);
    qtest_add_func("/migration/validate_uuid_dst_not_set",
                   test_validate_uuid_dst_not_set);
    qtest_add_func("/migration/auto_converge", test_migrate_auto_converge);
    qtest_add_func("/migration/auto_converge_force",
                   test_migrate_auto_converge_force);

    ret = g_test_run();

    g_assert_cmpint(ret, ==, 0);

    ret = rmdir(tmpfs);
    if (ret != 0) {
        g_test_message("unable to rmdir: path (%s): %s\n",
                       tmpfs, strerror(errno));
    }

    return ret;
}
