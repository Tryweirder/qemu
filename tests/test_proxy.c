/*
 * Test proxy application for AFL fuzzing and virtio test case verification.
 *
 * Copyright Yandex N.V. 2019
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>
#include <sys/epoll.h>
#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/libqos-pc.h"
#include "libqos/libqos-spapr.h"
#include "libqos/virtio.h"
#include "libqos/virtio-pci.h"
#include "libqos/virtio-mmio.h"
#include "libqos/malloc-generic.h"
#include "qemu/bswap.h"
#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_config.h"
#include "standard-headers/linux/virtio_ring.h"
#include "standard-headers/linux/virtio_blk.h"
#include "standard-headers/linux/virtio_pci.h"

#define TEST_IMAGE_SIZE         (64 * 1024 * 1024)
#define QVIRTIO_BLK_TIMEOUT_US  (30 * 1000 * 1000)
#define PCI_SLOT_HP             0x06
#define PCI_SLOT                0x04
#define PCI_FN                  0x00

#define FILENAME_PATH_MAX 128
#define BUFLEN 256

typedef struct QVirtioBlkReq {
    uint32_t type;
    uint32_t ioprio;
    uint64_t sector;
    char *data;
    uint8_t status;
} QVirtioBlkReq;

struct qtest_vqdev_s {
    QOSState *qs;
    QVirtioPCIDevice *dev;
    QVirtQueuePCI *vqpci;
};

struct test_proxy_opt_s {
    char afl_sock_path[FILENAME_PATH_MAX];
    char qtest_sock_path[FILENAME_PATH_MAX];
    char file_name[FILENAME_PATH_MAX];
    int mode;
};

static struct test_proxy_opt_s g_test_proxy_opt;

enum {
    PROXY_MODE_FILE,
    PROXY_MODE_AFL,
    PROXY_MODE_MAX
};

static int
parse_arguments(int argc, char *argv[])
{
    int opt;

    memset(&g_test_proxy_opt, 0, sizeof(g_test_proxy_opt));
    g_test_proxy_opt.mode = PROXY_MODE_MAX;
    while ((opt = getopt(argc, argv, "a:q:t:")) != -1) {
        switch (opt) {
        case 't':
            strncpy(g_test_proxy_opt.file_name, optarg,
                    FILENAME_PATH_MAX - 1);
            break;
        case 'a':
            strncpy(g_test_proxy_opt.afl_sock_path, optarg,
                    FILENAME_PATH_MAX - 1);
            break;
        case 'q':
            strncpy(g_test_proxy_opt.qtest_sock_path, optarg,
                    FILENAME_PATH_MAX - 1);
            break;
        default:
            printf("Parse error\n");
            return EINVAL;
        }
    }

    if (!strlen(g_test_proxy_opt.qtest_sock_path)) {
        printf("The qtest unix socket should be defined.\n");
        return EINVAL;
    }
    if (strlen(g_test_proxy_opt.file_name) && strlen(g_test_proxy_opt.afl_sock_path)) {
        printf("Use only one option explicitely: -a or -t.\n");
        return EINVAL;
    }
    if (strlen(g_test_proxy_opt.file_name)) {
        g_test_proxy_opt.mode = PROXY_MODE_FILE;
    } else if (strlen(g_test_proxy_opt.afl_sock_path)) {
        g_test_proxy_opt.mode = PROXY_MODE_AFL;
    } else {
        /* Other modes, if any. */
    }

    if (g_test_proxy_opt.mode >= PROXY_MODE_MAX) {
        printf("Can't set the proper proxy mode.\n");
        return EINVAL;
    }

    return 0;
}

static int
prepare_sock_path(const char *path)
{
    struct stat buf;

    if (stat(path, &buf) == -1) {
        if (errno == ENOENT) {
            return 0;
        } else {
            return errno;
        }
    }

    if (!S_ISSOCK(buf.st_mode)) {
        return EINVAL;
    }

    if (unlink(path) == -1) {
        return errno;
    }

    return 0;
}

static int
unix_sock_create(const char *path)
{
    int fd;
    struct sockaddr_un sockaddr;
    int ret;

    ret = prepare_sock_path(path);
    if (ret) {
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("Can't create new socket.\n");
        return -1;
    }

    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sun_family = AF_UNIX;
    strncpy(sockaddr.sun_path, path, sizeof(sockaddr.sun_path) - 1);
    if (bind(fd, (struct sockaddr*)&sockaddr,
                sizeof(sockaddr)) < 0) {
        printf("Can't bind socket.\n");
        close(fd);
        return -1;
    }

    if (listen(fd, 1) < 0) {
        printf("Can't listen socket.\n");
        close(fd);
        return -1;
    }
    printf("Unix socket created successfully: %s\n", path);

    return fd;
}

/*static int
unix_sock_connect(const char *path)
{
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("Can't create AF_UNIX socket.\n");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr,
                sizeof(addr)) == -1) {
        printf("Can't connect to socket = %s.\n", path);
        return -1;
    }

    return fd;
}*/

/*static void
do_proxy(int afl_fd, int user_fd)
{
	struct msghdr msgh;
	char control[CMSG_SPACE(sizeof(int) * 8)];
	strut iovec iov;
	char buf[256];
	int len;

	while (1) {
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);
		msgh.msg_name = NULL;
		msgh.msg_namelen = 0;
		msgh.msg_iov = &iov;
		msgh.msg_iovlen = 1;
		msgh.msg_control = control;
		msgh.msg_controllen = CMSG_SPACE(sizeof(int) * 8);
		len = recvmsg(afl_fd, &msgh, 0);
		if (len < 0) {
			printf("Can't receive message.\n");
			break;
		}

		iov.iov_len = len;
		if (sendmsg(user_fd, &msgh, 0) < 0) {
			printf("Can't send message.\n");
			break;
		}
	}
}*/

static int
send_unix_sock(int qtest_fd, char *buf, int len)
{
    struct msghdr msgh;
	struct iovec iov;
    int ret;

    iov.iov_base = buf;
    iov.iov_len = len;
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = NULL;
    msgh.msg_controllen = 0;
    ret = sendmsg(qtest_fd, &msgh, 0);
    if (ret < 0) {
        printf("Can't send message: %d: %s.\n", errno, strerror(errno));
        return ret;
    }

    return ret;
}

static int
recv_unix_sock(int qtest_fd, char *buf, int len)
{
    struct msghdr msgh;
    char control[CMSG_SPACE(sizeof(int) * 8)];
    struct iovec iov;
    int ret;

    iov.iov_base = buf;
    iov.iov_len = len;
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = control;
    msgh.msg_controllen = CMSG_SPACE(sizeof(int) * 8);
    ret = recvmsg(qtest_fd, &msgh, 0);
    if (ret < 0) {
        printf("Can't recv message: %d: %s.\n", errno, strerror(errno));
        return ret;
    }

    return ret;
}

static void
do_interactive(int qtest_fd)
{
    char buf[BUFLEN];
    int len;
    int ret;

    buf[0] = 0;
    buf[BUFLEN - 1] = 0;
    while (1) {
        printf("qtest cmd> ");
        fflush(stdout);
        len = read(STDIN_FILENO, buf, BUFLEN);
        if (len >= BUFLEN) {
            printf("The command is too long len = %d, enter another command. The size of the command should be less than %d.\n",
                    len, BUFLEN);
            continue;
        }

        ret = send_unix_sock(qtest_fd, buf, len);
        if (ret != len) {
            break;
        }
        ret = recv_unix_sock(qtest_fd, buf, BUFLEN);
        if (ret < 0) {
            break;
        }
        if (ret == BUFLEN) {
            ret--;
        }
        buf[ret] = 0;
        printf("%s", buf);
    }
}

static QVirtioPCIDevice *virtio_blk_pci_init(QPCIBus *bus, int slot)
{
    QVirtioPCIDevice *dev;

    dev = qvirtio_pci_device_find_slot(bus, VIRTIO_ID_BLOCK, slot);
    g_assert(dev != NULL);
    g_assert_cmphex(dev->vdev.device_type, ==, VIRTIO_ID_BLOCK);
    g_assert_cmphex(dev->pdev->devfn, ==, ((slot << 3) | PCI_FN));

    qvirtio_pci_device_enable(dev);
    qvirtio_reset(&dev->vdev);
    qvirtio_set_acknowledge(&dev->vdev);
    qvirtio_set_driver(&dev->vdev);

    return dev;
}

static inline void virtio_blk_fix_request(QVirtioDevice *d, QVirtioBlkReq *req)
{
#ifdef HOST_WORDS_BIGENDIAN
    const bool host_is_big_endian = true;
#else
    const bool host_is_big_endian = false;
#endif

    if (qvirtio_is_big_endian(d) != host_is_big_endian) {
        req->type = bswap32(req->type);
        req->ioprio = bswap32(req->ioprio);
        req->sector = bswap64(req->sector);
    }
}

static uint64_t virtio_blk_request(QGuestAllocator *alloc, QVirtioDevice *d,
                                   QVirtioBlkReq *req, uint64_t data_size)
{
    uint64_t addr;
    uint8_t status = 0xFF;

    g_assert_cmpuint(data_size % 512, ==, 0);
    addr = guest_alloc(alloc, sizeof(*req) + data_size);

    virtio_blk_fix_request(d, req);

    memwrite(addr, req, 16);
    memwrite(addr + 16, req->data, data_size);
    memwrite(addr + 16 + data_size, &status, sizeof(status));

    return addr;
}

static void
qos_state_init(struct qtest_vqdev_s *qvq, int qtest_fd, int qmp_fd)
{
    QOSState *qs;
    QVirtioPCIDevice *dev;
    QVirtQueuePCI *vqpci;
    uint64_t capacity;
    uint32_t features;

    qs = qtest_pc_vmconnect(qtest_fd, qmp_fd);//(NULL, NULL, PCI_SLOT, PCI_FN, "");
    global_qtest = qs->qts;

    dev = virtio_blk_pci_init(qs->pcibus, PCI_SLOT);
    qpci_msix_enable(dev->pdev);

    qvirtio_pci_set_msix_configuration_vector(dev, qs->alloc, 0);

    capacity = qvirtio_config_readq(&dev->vdev, 0);
    g_assert_cmpint(capacity, ==, TEST_IMAGE_SIZE / 512);

    features = qvirtio_get_features(&dev->vdev);
    features = features & ~(QVIRTIO_F_BAD_FEATURE |
                            (1u << VIRTIO_RING_F_INDIRECT_DESC) |
                            (1u << VIRTIO_F_NOTIFY_ON_EMPTY) |
                            (1u << VIRTIO_BLK_F_SCSI));
    qvirtio_set_features(&dev->vdev, features);

    vqpci = (QVirtQueuePCI *)qvirtqueue_setup(&dev->vdev, qs->alloc, 0);
    qvirtqueue_pci_msix_setup(dev, vqpci, qs->alloc, 1);

    qvirtio_set_driver_ok(&dev->vdev);

    qvq->qs = qs;
    qvq->dev = dev;
    qvq->vqpci = vqpci;
}

static void
qos_state_cleanup(struct qtest_vqdev_s *qvq)
{
    QOSState *qs;
    QVirtioPCIDevice *dev;
    QVirtQueuePCI *vqpci;

    qs = qvq->qs;
    dev = qvq->dev;
    vqpci = qvq->vqpci;

    qvirtqueue_cleanup(dev->vdev.bus, &vqpci->vq, qs->alloc);
    qpci_msix_disable(dev->pdev);
    qvirtio_pci_device_disable(dev);
    qvirtio_pci_device_free(dev);
    global_qtest = NULL;
    /* Shutdown/free for qs and its fields, can't use qtest_shutdown()
     * because of there is no qemu pid.
     */
}

static void
send_vq_data(struct qtest_vqdev_s *qvq, char *buf, int len)
{
    QVirtioPCIDevice *dev;
    QVirtQueuePCI *vqpci;
    QVirtQueue *vq;
    uint16_t idx;

    dev = qvq->dev;
    vqpci = qvq->vqpci;

    vq = &vqpci->vq;
    memwrite(vq->desc, buf, len);
    /* vq->avail->idx */
    idx = readw(vq->avail + 2);
    printf("idx = %d\n", idx);
    /* vq->avail->ring[idx % vq->size] */
    writew(vq->avail + 4 + (2 * (idx % vq->size)), 0);
    /* vq->avail->idx */
    writew(vq->avail + 2, idx + 1);

    /* kick */
    dev->vdev.bus->virtqueue_kick(&dev->vdev, vq);
}

static void
show_vq_ptrs(struct qtest_vqdev_s *qvq)
{
    QVirtQueue *vq;

    vq = &qvq->vqpci->vq;
    printf("vq->desc = %lx\n", vq->desc);
    printf("vq->avail = %lx\n", vq->avail);
    printf("vq->used = %lx\n", vq->used);
    printf("vq->size = %u\n", vq->size);
}

static void
send_vq_request(struct qtest_vqdev_s *qvq)
{
    QOSState *qs;
    QVirtioPCIDevice *dev;
    QVirtQueuePCI *vqpci;
    QVirtioBlkReq req;
    uint64_t req_addr;
    uint32_t free_head;
    uint32_t write_head;
    uint32_t desc_idx;
    uint8_t status;
    char *data;

    qs = qvq->qs;
    dev = qvq->dev;
    vqpci = qvq->vqpci;

    /* Write request */
    req.type = VIRTIO_BLK_T_OUT;
    req.ioprio = 1;
    req.sector = 0;
    req.data = g_malloc0(512);
    strcpy(req.data, "TEST");

    req_addr = virtio_blk_request(qs->alloc, &dev->vdev, &req, 512);

    g_free(req.data);

    free_head = qvirtqueue_add(&vqpci->vq, req_addr, 16, false, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 16, 512, false, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 528, 1, true, false);
    qvirtqueue_kick(&dev->vdev, &vqpci->vq, free_head);

    qvirtio_wait_used_elem(&dev->vdev, &vqpci->vq, free_head, NULL,
                           QVIRTIO_BLK_TIMEOUT_US);

    /* Write request */
    req.type = VIRTIO_BLK_T_OUT;
    req.ioprio = 1;
    req.sector = 1;
    req.data = g_malloc0(512);
    strcpy(req.data, "TEST");

    req_addr = virtio_blk_request(qs->alloc, &dev->vdev, &req, 512);

    g_free(req.data);

    /* Notify after processing the third request */
    qvirtqueue_set_used_event(&vqpci->vq, 2);
    free_head = qvirtqueue_add(&vqpci->vq, req_addr, 16, false, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 16, 512, false, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 528, 1, true, false);
    qvirtqueue_kick(&dev->vdev, &vqpci->vq, free_head);
    write_head = free_head;

    /* No notification expected */
    status = qvirtio_wait_status_byte_no_isr(&dev->vdev,
                                             &vqpci->vq, req_addr + 528,
                                             QVIRTIO_BLK_TIMEOUT_US);
    g_assert_cmpint(status, ==, 0);

    guest_free(qs->alloc, req_addr);

    /* Read request */
    req.type = VIRTIO_BLK_T_IN;
    req.ioprio = 1;
    req.sector = 1;
    req.data = g_malloc0(512);

    req_addr = virtio_blk_request(qs->alloc, &dev->vdev, &req, 512);

    g_free(req.data);

    free_head = qvirtqueue_add(&vqpci->vq, req_addr, 16, false, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 16, 512, true, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 528, 1, true, false);

    qvirtqueue_kick(&dev->vdev, &vqpci->vq, free_head);

    /* We get just one notification for both requests */
    qvirtio_wait_used_elem(&dev->vdev, &vqpci->vq, write_head, NULL,
                           QVIRTIO_BLK_TIMEOUT_US);
    g_assert(qvirtqueue_get_buf(&vqpci->vq, &desc_idx, NULL));
    g_assert_cmpint(desc_idx, ==, free_head);

    status = readb(req_addr + 528);
    g_assert_cmpint(status, ==, 0);

    data = g_malloc0(512);
    memread(req_addr + 16, data, 512);
    g_assert_cmpstr(data, ==, "TEST");
    g_free(data);

    guest_free(qs->alloc, req_addr);
}

#if 0
static void
qos_state_init(int qtest_fd, int qmp_fd)
{
    QOSState *qs;
    QVirtioPCIDevice *dev;
    QVirtQueuePCI *vqpci;
    QVirtioBlkReq req;
    uint64_t req_addr;
    uint64_t capacity;
    uint32_t features;
    uint32_t free_head;
    uint32_t write_head;
    uint32_t desc_idx;
    uint8_t status;
    char *data;

    qs = qtest_pc_vmconnect(qtest_fd, qmp_fd);//(NULL, NULL, PCI_SLOT, PCI_FN, "");
    global_qtest = qs->qts;

    dev = virtio_blk_pci_init(qs->pcibus, PCI_SLOT);
    qpci_msix_enable(dev->pdev);

    qvirtio_pci_set_msix_configuration_vector(dev, qs->alloc, 0);

    capacity = qvirtio_config_readq(&dev->vdev, 0);
    g_assert_cmpint(capacity, ==, TEST_IMAGE_SIZE / 512);

    features = qvirtio_get_features(&dev->vdev);
    features = features & ~(QVIRTIO_F_BAD_FEATURE |
                            (1u << VIRTIO_RING_F_INDIRECT_DESC) |
                            (1u << VIRTIO_F_NOTIFY_ON_EMPTY) |
                            (1u << VIRTIO_BLK_F_SCSI));
    qvirtio_set_features(&dev->vdev, features);

    vqpci = (QVirtQueuePCI *)qvirtqueue_setup(&dev->vdev, qs->alloc, 0);
    qvirtqueue_pci_msix_setup(dev, vqpci, qs->alloc, 1);

    qvirtio_set_driver_ok(&dev->vdev);

    /* Write request */
    req.type = VIRTIO_BLK_T_OUT;
    req.ioprio = 1;
    req.sector = 0;
    req.data = g_malloc0(512);
    strcpy(req.data, "TEST");

    req_addr = virtio_blk_request(qs->alloc, &dev->vdev, &req, 512);

    g_free(req.data);

    free_head = qvirtqueue_add(&vqpci->vq, req_addr, 16, false, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 16, 512, false, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 528, 1, true, false);
    qvirtqueue_kick(&dev->vdev, &vqpci->vq, free_head);

    qvirtio_wait_used_elem(&dev->vdev, &vqpci->vq, free_head, NULL,
                           QVIRTIO_BLK_TIMEOUT_US);

    /* Write request */
    req.type = VIRTIO_BLK_T_OUT;
    req.ioprio = 1;
    req.sector = 1;
    req.data = g_malloc0(512);
    strcpy(req.data, "TEST");

    req_addr = virtio_blk_request(qs->alloc, &dev->vdev, &req, 512);

    g_free(req.data);

    /* Notify after processing the third request */
    qvirtqueue_set_used_event(&vqpci->vq, 2);
    free_head = qvirtqueue_add(&vqpci->vq, req_addr, 16, false, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 16, 512, false, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 528, 1, true, false);
    qvirtqueue_kick(&dev->vdev, &vqpci->vq, free_head);
    write_head = free_head;

    /* No notification expected */
    status = qvirtio_wait_status_byte_no_isr(&dev->vdev,
                                             &vqpci->vq, req_addr + 528,
                                             QVIRTIO_BLK_TIMEOUT_US);
    g_assert_cmpint(status, ==, 0);

    guest_free(qs->alloc, req_addr);

    /* Read request */
    req.type = VIRTIO_BLK_T_IN;
    req.ioprio = 1;
    req.sector = 1;
    req.data = g_malloc0(512);

    req_addr = virtio_blk_request(qs->alloc, &dev->vdev, &req, 512);

    g_free(req.data);

    free_head = qvirtqueue_add(&vqpci->vq, req_addr, 16, false, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 16, 512, true, true);
    qvirtqueue_add(&vqpci->vq, req_addr + 528, 1, true, false);

    qvirtqueue_kick(&dev->vdev, &vqpci->vq, free_head);

    /* We get just one notification for both requests */
    qvirtio_wait_used_elem(&dev->vdev, &vqpci->vq, write_head, NULL,
                           QVIRTIO_BLK_TIMEOUT_US);
    g_assert(qvirtqueue_get_buf(&vqpci->vq, &desc_idx, NULL));
    g_assert_cmpint(desc_idx, ==, free_head);

    status = readb(req_addr + 528);
    g_assert_cmpint(status, ==, 0);

    data = g_malloc0(512);
    memread(req_addr + 16, data, 512);
    g_assert_cmpstr(data, ==, "TEST");
    g_free(data);

    guest_free(qs->alloc, req_addr);

    /* End test */
    qvirtqueue_cleanup(dev->vdev.bus, &vqpci->vq, qs->alloc);
    qpci_msix_disable(dev->pdev);
    qvirtio_pci_device_disable(dev);
    qvirtio_pci_device_free(dev);
    global_qtest = NULL;
    /* Shutdown/free for qs and its fields, can't use qtest_shutdown()
     * because of there is no qemu pid.
     */
}
#endif

static int
virtio_send_file(const char *file_name, struct qtest_vqdev_s *qvq)
{
    int fd;
    off_t size;
    char *buf;
    int ret;

    ret = 0;
    fd = open(file_name, O_RDONLY);
    if (fd == -1) {
        printf("Can't open file %s: %d, %s.\n",
                file_name, errno, strerror(errno));
        ret = errno;
        goto close_file;
    }
    size = lseek(fd, 0, SEEK_END);
    if (size == (off_t)-1) {
        printf("Can't get the size of the file: %d, %s.\n",
                errno, strerror(errno));
        ret = errno;
        goto close_file;
    }
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        printf("Can't reset the start position for the file: %d, %s.\n",
                errno, strerror(errno));
        ret = errno;
        goto close_file;
    }

    buf = malloc(size);
    if (!buf) {
        printf("Can't allocate buffer of size = %ld: %d, %s.\n",
                size, errno, strerror(errno));
        ret = errno;
        goto close_file;
    }
    if (read(fd, buf, size) != size) {
        printf("Can't read file of size = %ld: %d, %s.\n",
                size, errno, strerror(errno));
        ret = errno;
        goto free_buf;
    }

    send_vq_data(qvq, buf, size);

free_buf:
    free(buf);
close_file:
    close(fd);

    return ret;
}

static void
buf_dump(const char *buf, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (!(i % 16)) {
            printf("\n");
        }
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

#define MAX_EVENTS 1
#define AFL_BUF_LEN 65536
static char g_afl_buf[AFL_BUF_LEN];

static int
handle_io(int qtest_srv, int afl_fd, struct test_proxy_opt_s *opt)
{
    int qtest_fd;
    int epoll_fd;
    struct epoll_event ev;
    struct epoll_event events[MAX_EVENTS];
    int i;
    int len;
    int nfds;
    struct qtest_vqdev_s qtest_vqdev;

    qtest_fd = -1;

    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        printf("Can't create epoll fd: %d, %s\n",
                errno, strerror(errno));
        return errno;
    }

    ev.events = EPOLLIN;
    ev.data.fd = qtest_srv;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, qtest_srv, &ev) == -1) {
        printf("Can't add qtest_srv = %d file descriptor to epoll_fd = %d: %d, %s\n",
                qtest_srv, epoll_fd, errno, strerror(errno));
        return errno;
    }
    if (afl_fd != -1) {
        ev.events = EPOLLIN;
        ev.data.fd = qtest_srv;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, afl_fd, &ev) == -1) {
            printf("Can't add afl_fd = %d file descriptor to epoll_fd = %d: %d, %s\n",
                    afl_fd, epoll_fd, errno, strerror(errno));
            return errno;
        }
    }

    while (1) {
        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            printf("Poll error on epoll_fd = %d: %d, %s.\n",
                    epoll_fd, errno, strerror(errno));
            return errno;
        }

        for (i = 0; i < nfds; i++) {
            if (events[i].data.fd == qtest_srv) {
                if (qtest_fd != -1) {
                    printf("Connection in use.\n");
                    continue;
                }

                /* New connection. */
                qtest_fd = accept(qtest_srv, NULL, NULL);
                if (qtest_fd == -1) {
                    printf("Can't accept qtest connection: %d, %s.\n",
                            errno, strerror(errno));
                    return errno;
                }

                memset(&qtest_vqdev, 0, sizeof(qtest_vqdev));
                qos_state_init(&qtest_vqdev, qtest_fd, -1);
                show_vq_ptrs(&qtest_vqdev);

                if (opt->mode == PROXY_MODE_FILE) {
                    virtio_send_file(opt->file_name, &qtest_vqdev);
                    qos_state_cleanup(&qtest_vqdev);
                    return 0;
                }

                ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
                ev.data.fd = qtest_fd;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, qtest_fd, &ev) == -1) {
                    printf("Can't add qtest_fd = %d file descriptor to epoll_fd = %d: %d, %s\n",
                            qtest_fd, epoll_fd, errno, strerror(errno));
                    return errno;
                }
            } else if (events[i].data.fd == afl_fd) {
                len = recv_unix_sock(events[i].data.fd, g_afl_buf, AFL_BUF_LEN);
                if (len < 0) {
                    return len;
                }
                printf("Get data from AFL, len = %d.\n", len);
                buf_dump(g_afl_buf, len);
            } else if (events[i].data.fd == qtest_fd) {
                if ((events[i].events & EPOLLERR) ||
                        (events[i].events & (EPOLLHUP | EPOLLRDHUP))) {
                    /* Close qtest connection. */
                    qos_state_cleanup(&qtest_vqdev);
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, qtest_fd, NULL);
                    close(qtest_fd);
                    qtest_fd = -1;
                } else if (events[i].events == EPOLLIN) {
                    /* There is some data to read, but we don't care for now. */
                }
            }
        }
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    int ret;
    int afl_srv;
    int afl_fd;
    int qtest_srv;

    ret = parse_arguments(argc, argv);
    if (ret) {
        return ret;
    }

    afl_fd = -1;
    if (g_test_proxy_opt.mode == PROXY_MODE_AFL) {
        afl_srv = unix_sock_create(g_test_proxy_opt.afl_sock_path);
        if (afl_srv == -1) {
            return -1;
        }
        printf("Waiting for the connection on %s unix socket.\n", g_test_proxy_opt.afl_sock_path);
        afl_fd = accept(afl_srv, NULL, NULL);
        if (afl_fd == -1) {
            printf("Can't accept connection.\n");
            return -1;
        }
    }
    printf("Connection successful.\n");

    qtest_srv = unix_sock_create(g_test_proxy_opt.qtest_sock_path);
    if (qtest_srv == -1) {
        return -1;
    }

    handle_io(qtest_srv, afl_fd, &g_test_proxy_opt);

    return 0;

    send_vq_request(NULL);
    do_interactive(-1);
    /*printf("Start proxy\n");
    do_proxy(afl_fd, user_fd);*/

    return 0;
}
