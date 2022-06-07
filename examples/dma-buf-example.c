// Test code for DMA buffer

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <liburing.h>
#include <string.h>
#include "../../libraries.os.memory.dma-buf-exporter-kmd/dma_buf_exporter_kmd.h"

#define URING_QD 32

#if 0
/* TBD: copied common code from dma-exporter code, include header file when available */
struct dma_exporter_buf_alloc_data {
	uint32_t fd;
	uint64_t size;
	uint32_t reserved [3];
};

#define DMA_BUF_EXPORTER_MAGIC		'D'

#define DMA_BUF_EXPORTER_ALLOC		_IOWR(DMA_BUF_EXPORTER_MAGIC, 0, \
				      struct dma_exporter_buf_alloc_data)

#define DMA_BUF_EXPORTER_FREE     _IOWR(DMA_BUF_EXPORTER_MAGIC, 8, \
					struct dma_exporter_buf_alloc_data)
#endif

struct global_context {
	struct io_uring *ring;
	uint64_t offset;
	uint32_t len;
	uint32_t qdepth;
	int fd_io_device;
	int fd_dmabuf_exporter_dev;
	struct dma_exporter_buf_alloc_data data;
	int fd_dmabuf;
	uint8_t write;
};

struct global_context *g_ctxt;

void free_global_ctxt(void)
{
    if (g_ctxt->fd_dmabuf_exporter_dev) {
	    close(g_ctxt->fd_dmabuf_exporter_dev);
    }
    if (g_ctxt->fd_io_device) {
	    close(g_ctxt->fd_io_device);
    }
    if (g_ctxt->ring){
	    free(g_ctxt->ring);
    }
    if (g_ctxt->fd_dmabuf) {
	    close(g_ctxt->fd_dmabuf);
    }
    free(g_ctxt);
}

int init_global_ctxt(int argc, char *argv[])
{
	g_ctxt = calloc(1, sizeof(struct global_context));
	if (!g_ctxt) {
		printf("Unable to allocate g_ctxt\n");
		return -1;
	}
	g_ctxt->ring = calloc(1, sizeof(struct io_uring));
	if (!g_ctxt->ring) {
		printf("Unable to alloate io_uring memory\n");
		return -1;
	}
	g_ctxt->qdepth = URING_QD;

	printf ("Opening file %s ... \n", argv[1]);
	g_ctxt->fd_io_device = open(argv[1], O_RDWR);
	if (g_ctxt->fd_io_device < 0) {
		printf("Unable to open fd for io device %s\n", argv[1]);
		return -1;
	}

	printf ("Opening DMA buf exporter driver device  %s ... \n", argv[2]);
	g_ctxt->fd_dmabuf_exporter_dev = open(argv[2], O_RDWR);
	if (g_ctxt->fd_dmabuf_exporter_dev < 0) {
		printf("Unable to open fd for dma buf exporter device %s\n", argv[2]);
		return -1;
	}


	printf ("\n %s, %s, %s \n", argv[3], argv[4], argv[5]);
	g_ctxt->write = atoi(argv[3]);
	g_ctxt->offset = atoi(argv[4]);
	g_ctxt->len = atoi(argv[5]);

	printf("Read/Write: %d, Offset: %d, Length: %d \n", g_ctxt->write, g_ctxt->offset, g_ctxt->len);
	return 0;
}

/* argv[1] = filepath1 for IO device
 * argv[2] = filepatah2 for DMA BUF Exporter Device
 * argv[3] = direction from filepath1 -> filepath2
 * argv[4] = offset
 * argv[5] = length
 */
int main(int argc, char *argv[])
{
	struct io_uring_sqe *sq_entry;
	int ret;
	struct io_uring_cqe *cq_entry;

	if (argc < 6) {
		printf ("Invalid arguements %d \n", argc);
		printf ("\nUsage: %s <File Path on IO Device> <DMa Buf Exporter Driver Node Path> <Read/Write 0:1> <Read/Write Offset in bytes> <Length in bytes> \n", argv[0]);
		printf ("\nExample: %s ./sample-text-file.txt /dev/dma_buf_exporter 0 0 4 \n\n", argv[0]);
		return -1;
	}

	memset(&g_ctxt, 0, sizeof(g_ctxt));
	if (init_global_ctxt(argc, argv) < 0) {
		printf("init failed\n");
		free_global_ctxt();
		return -1;
	}

	printf("Initializing io_uring queue ...\n");
	if (io_uring_queue_init(g_ctxt->qdepth, g_ctxt->ring, 0) < 0) {
		printf("Unable to init IO uring\n");
		free_global_ctxt();
		return -1;
	}

	printf("Allocating dma_buf ...\n");
	g_ctxt->data.size = g_ctxt->len;
	if (ioctl(g_ctxt->fd_dmabuf_exporter_dev, DMA_BUF_EXPORTER_ALLOC, &g_ctxt->data) != 0) {
		printf("ioctl 11 for allocate dma buffer fd failed\n");
		free_global_ctxt();
		return -1;
	}
	g_ctxt->fd_dmabuf = g_ctxt->data.fd;
	if (g_ctxt->fd_dmabuf <=0 ) {
		printf("Unable to get buffer fd from GPU KMD\n");
		free_global_ctxt();
	}

	printf("Getting sqe entry ...\n");
	sq_entry = io_uring_get_sqe(g_ctxt->ring);
	if (!sq_entry) {
		printf("Unable to allocate sq_entry\n");
		free_global_ctxt();
		return -1;
	}

	printf("Prepering IO request ...\n");
	if (g_ctxt->write) {
		printf("test write ... \n");
		io_uring_prep_write_dma(sq_entry, g_ctxt->fd_io_device, g_ctxt->fd_dmabuf, g_ctxt->offset, g_ctxt->len);
	} else {
		printf("test read ... \n");
		io_uring_prep_read_dma(sq_entry, g_ctxt->fd_io_device, g_ctxt->fd_dmabuf, g_ctxt->offset, g_ctxt->len);
	}

	printf("Submiting IO request ...\n");
	ret = io_uring_submit(g_ctxt->ring);
	if (ret < 0) {
		printf("Unable to submit IO uring request\n");
		free_global_ctxt();
		return -1;
	}

	printf("Waiting for IO request to complete ...\n");
	if (io_uring_wait_cqe(g_ctxt->ring, &cq_entry) < 0) {
		printf("Unable to get cq_entry\n");
		free_global_ctxt();
		return -1;
	}

	printf("Freeint up IO request resources ...\n");
	
	io_uring_cqe_seen(g_ctxt->ring, cq_entry);
        if (ioctl(g_ctxt->fd_dmabuf_exporter_dev, DMA_BUF_EXPORTER_FREE, g_ctxt->data.fd) != 0) {
		printf("Unable to deallocate dma buffer\n");
		free_global_ctxt();
		return -1;
	}


	io_uring_queue_exit(g_ctxt->ring);
	free_global_ctxt();

	return 0;
}
