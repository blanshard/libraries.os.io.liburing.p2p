// Test code for DMA buffer

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <liburing.h>
#include <string.h>

#define URING_QD 8

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

#define DMA_BUF_EXPORTER_DEVICE 	"/dev/dma_buf_exporter"

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

	g_ctxt->fd_io_device = open(argv[1], O_RDWR);
	if (g_ctxt->fd_io_device < 0) {
		printf("Unable to open fd for io device %s\n", argv[1]);
		return -1;
	}

	g_ctxt->fd_dmabuf_exporter_dev = open(DMA_BUF_EXPORTER_DEVICE, O_RDWR);

	printf("fd_dmabuf_exporter_dev: %d \n", g_ctxt->fd_dmabuf_exporter_dev);

	if (g_ctxt->fd_dmabuf_exporter_dev < 0) {
		printf("Unable to open fd for dma buf exporter device %s error:%d\n", argv[2], g_ctxt->fd_dmabuf_exporter_dev);
		return -1;
	}

	g_ctxt->write  = atoi(argv[2]);
	g_ctxt->offset = atoi(argv[3]);
	g_ctxt->len    = atoi(argv[4]);

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
	struct io_uring_sqe *sqe;
	int ret;
	struct io_uring_cqe *cqe;
	struct iovec iov;

	memset(&g_ctxt, 0, sizeof(g_ctxt));

	printf("global ctx initialization: \n");

	if (init_global_ctxt(argc, argv) < 0) {
		printf("init failed\n");
		free_global_ctxt();
		return -1;
	}

	printf("io uring queue init: \n");

	if (io_uring_queue_init(g_ctxt->qdepth, g_ctxt->ring, 0) < 0) {
		printf("Unable to init IO uring\n");
		free_global_ctxt();
		return -1;
	}

	printf("allocate dma buff: \n");
	g_ctxt->data.size = g_ctxt->len;
	if (ioctl(g_ctxt->fd_dmabuf_exporter_dev, DMA_BUF_EXPORTER_ALLOC, &g_ctxt->data) != 0) {
		printf("ioctl for allocate dma buffer fd failed\n");
		free_global_ctxt();
		return -1;
	}

	g_ctxt->fd_dmabuf = g_ctxt->data.fd;

	printf("g_ctxt->fd_dmabuf: %d\n", g_ctxt->fd_dmabuf);
	if (g_ctxt->fd_dmabuf <=0 ) {
		printf("Unable to get buffer fd from GPU KMD\n");
		free_global_ctxt();
	}

	sqe = io_uring_get_sqe(g_ctxt->ring);
	if (!sqe) {
		printf("Unable to allocate sqe\n");
		free_global_ctxt();
		return -1;
	}
	
	printf("-------------io_uring prep: ------------\n");
	printf("fd_io_device: %d \n", 	g_ctxt->fd_io_device);
	printf("fd_dmabuf: %d \n", 		g_ctxt->fd_dmabuf);
	printf("offset: %d \n", 		g_ctxt->offset);	
	printf("write: %d \n", 			g_ctxt->write);
	printf("len: %d \n", 			g_ctxt->len);

	//free_global_ctxt();
	//return 0;

	void *buf;
	posix_memalign(&buf, 4096, g_ctxt->len);

	iov.iov_base = buf;
	iov.iov_len  = g_ctxt->len;	

/*
	if (g_ctxt->write)
		io_uring_prep_write(sqe, g_ctxt->fd_io_device, buf, g_ctxt->len, g_ctxt->offset);
	else
		io_uring_prep_read(sqe,  g_ctxt->fd_io_device, buf, g_ctxt->len, g_ctxt->offset);
*/

/*
	if (g_ctxt->write)
		io_uring_prep_writev(sqe, g_ctxt->fd_io_device, &iov, 1, g_ctxt->offset);
	else
		io_uring_prep_readv(sqe,  g_ctxt->fd_io_device, &iov, 1, g_ctxt->offset);
*/

	printf("buf: %x\n", buf);

	if (g_ctxt->write) {
		io_uring_prep_write_dma(sqe, g_ctxt->fd_io_device, buf, g_ctxt->len, g_ctxt->offset, g_ctxt->fd_dmabuf);
	} else {
		io_uring_prep_read_dma(sqe, g_ctxt->fd_io_device, buf, g_ctxt->len, g_ctxt->offset, g_ctxt->fd_dmabuf);
	}

	printf("sqe->opcode %d\n", sqe->opcode);
	printf("sqe->flags %d\n", sqe->flags);
	printf("sqe->ioprio %d\n", sqe->ioprio);
	printf("sqe->fd %d\n", sqe->fd);
	printf("sqe->off %d\n", sqe->off);
	printf("sqe->addr %x\n", sqe->addr);
	printf("sqe->len %d\n", sqe->len);
	printf("sqe->rw_flags %d\n", sqe->rw_flags);
	printf("sqe->buf_index %d\n", sqe->buf_index);
	printf("sqe->personality %d\n", sqe->personality);
	printf("sqe->file_index %d\n", sqe->file_index);
	printf("sqe->fd_dma_buf %d\n", sqe->fd_dma_buf);

	ret = io_uring_submit(g_ctxt->ring);

	if (ret < 0) {
		printf("Unable to submit IO uring request\n");
		free_global_ctxt();
		return -1;
	}

	ret = io_uring_wait_cqe(g_ctxt->ring, &cqe);

	if (ret < 0) {
		printf("Unable to get cqe\n");
		free_global_ctxt();
		return -1;
	}

	io_uring_cqe_seen(g_ctxt->ring, cqe);
	printf("cqe ret: %d\n", ret);
	printf("cqe res: %d %s\n", cqe->res, strerror(-cqe->res));

	printf("---result-----\n");
	printf("%.*s \n", 4096, buf);

    if (ioctl(g_ctxt->fd_dmabuf_exporter_dev, DMA_BUF_EXPORTER_FREE, &g_ctxt->data) != 0) {
		printf("Unable to deallocate dma buffer\n");
		free_global_ctxt();
		return -1;
	}

	io_uring_queue_exit(g_ctxt->ring);
	free_global_ctxt();

	return 0;
}
