/*
 * OpenSSH Multi-threaded AES-CTR Cipher
 *
 * Author: Benjamin Bennett <ben@psc.edu>
 * Author: Mike Tasota <tasota@gmail.com>
 * Author: Chris Rapier <rapier@psc.edu>
 * Copyright (c) 2008-2021 Pittsburgh Supercomputing Center. All rights reserved.
 *
 * Based on original OpenSSH AES-CTR cipher. Small portions remain unchanged,
 * Copyright (c) 2003 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "includes.h"

#if defined(WITH_OPENSSL) && !defined(WITH_OPENSSL3)
#include <sys/types.h>

#include <stdarg.h>
#include <string.h>

#include <openssl/evp.h>

#include "xmalloc.h"
#include "log.h"
#include <unistd.h>
#include "uthash.h"

/* compatibility with old or broken OpenSSL versions */
#include "openbsd-compat/openssl-compat.h"

#ifndef USE_BUILTIN_RIJNDAEL
#include <openssl/aes.h>
#endif

#include <pthread.h>

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

/* note regarding threads and queues */
/* initially this cipher was written in a way that
 * the key stream was generated in a per cipher block
 * loop. For example, if the key stream queue length was
 * 16k and the cipher block size was 16 bytes it would
 * fill the queue 16 bytes at a time. Mitch Dorrell pointed
 * out that we could fill the queue in once call eliminating
 * loop and multiple calls to EVP_EncryptUpdate. Doing so
 * dramatically reduced CPU load in the threads and indicated
 * that we could also eliminate most of the threads and queues
 * as it would take far less time for a queue to ebter KQ_FULL
 * state. As such, we've reduced the default number of threads
 * and queues from 2 and 8 (respectively) to 1 and 2. We've also
 * elimnated the need to determine the physical number of cores on
 * the system and, if the user desires, can spin up more threads
 * using an environment variable. Additionally, queues is now fixed
 * at thread_count + 1.
 * cjr 10/19/2022 */

/*-------------------- TUNABLES --------------------*/
/* maximum number of threads and queues */
#define MAX_THREADS      4
#define MAX_NUMKQ        (MAX_THREADS + 1)

/* The number of pregen threads and keystream queues is chosen for each
 * cipher context in ssh_aes_ctr_init (SSH_CIPHER_THREADS). They are kept
 * in the context, not in globals. */

/* Length of a keystream queue */
/* one queue holds 512KB (1024 * 32 * 16) of key data
 * being that the queues are destroyed after a rekey
 * and at leats one has to be fully filled prior to
 * enciphering data we don't want this to be too large */
#define KQLEN (1024 * 32)

/* Processor cacheline length */
#define CACHELINE_LEN	64

/* Can the system do unaligned loads natively? */
#if defined(__aarch64__) || \
    defined(__i386__)    || \
    defined(__powerpc__) || \
    defined(__x86_64__)
# define CIPHER_UNALIGNED_OK
#endif
#if defined(__SIZEOF_INT128__)
# define CIPHER_INT128_OK
#endif
/*-------------------- END TUNABLES --------------------*/

#define HAVE_NONE       0
#define HAVE_KEY        1
#define HAVE_IV         2
int X = 0;

const EVP_CIPHER *evp_aes_ctr_mt(void);

/* Keystream Queue state */
enum {
	KQINIT,
	KQEMPTY,
	KQFILLING,
	KQFULL,
	KQDRAINING
};

/* Keystream Queue struct */
struct kq {
	u_char		keys[KQLEN][AES_BLOCK_SIZE]; /* [32768][16B] */
	u_char		ctr[AES_BLOCK_SIZE]; /* 16B */
	u_char          pad0[CACHELINE_LEN];
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	int             qstate;
	u_char          pad1[CACHELINE_LEN];
};

/* Context struct. Everything a pregen thread needs is in here, so no
 * state is shared between contexts through globals. */
struct ssh_aes_ctr_ctx_mt;

/* Arguments for one pregen thread. Embedded in the context, so it lives as
 * long as the context does and the thread can read it safely. */
struct pregen_job {
	struct ssh_aes_ctr_ctx_mt *ctx;
	int                        idx;
};

struct ssh_aes_ctr_ctx_mt
{
	long unsigned int struct_id;
	int keylen;      /* key length in bits */
	int threads;     /* pregen threads to start */
	int numkq;       /* keystream queues: threads + 1 */
	int running;     /* threads started and not yet joined */
	int state;
	int qidx;
	int ridx;
	int id[MAX_THREADS]; /* 32 */
	AES_KEY aes_key;
	/* Copy of the key. The caller's buffer is not guaranteed to outlive
	 * the init call, and the pregen threads read the key. */
	u_char key[32];
	u_char aes_counter[AES_BLOCK_SIZE]; /* 16B */
	pthread_t tid[MAX_THREADS]; /* 32 */
	/* Per-thread keystream contexts. Created and keyed before their thread
	 * starts; freed by stop_and_join after the thread has been joined. */
	EVP_CIPHER_CTX *evp[MAX_THREADS];
	struct pregen_job job[MAX_THREADS];
	struct kq q[MAX_NUMKQ]; /* 33 */
#ifdef __APPLE__
	pthread_rwlock_t stop_lock;
	int exit_flag;
#endif /* __APPLE__ */
};

/* globals */
/* how we increment the id the structs we create */
long unsigned int global_struct_id = 0;

/* An all-zero block of input for the keystream generator. It is only read,
 * so it is static rather than a 512KB array on each thread's stack. */
static const u_char mynull[KQLEN * AES_BLOCK_SIZE];

/*
 * Add num to counter 'ctr'
 */
static void
ssh_ctr_add(u_char *ctr, uint32_t num, u_int len)
{
	int i;
	uint16_t n;

	for (n = 0, i = len - 1; i >= 0 && (num || n); i--) {
		n = ctr[i] + (num & 0xff) + n;
		num >>= 8;
		ctr[i] = n & 0xff;
		n >>= 8;
	}
}

/*
 * Threads may be cancelled in a pthread_cond_wait, we must free the mutex
 */
static void
thread_loop_cleanup(void *x)
{
	pthread_mutex_unlock((pthread_mutex_t *)x);
}

#ifdef __APPLE__
/* Check if we should exit, we are doing both cancel and exit condition
 * since on OSX threads seem to occasionally fail to notice when they have
 * been cancelled. We want to have a backup to make sure that we won't hang
 * when the main process join()-s the cancelled thread.
 */
static void
thread_loop_check_exit(struct ssh_aes_ctr_ctx_mt *c)
{
	int exit_flag;

	pthread_rwlock_rdlock(&c->stop_lock);
	exit_flag = c->exit_flag;
	pthread_rwlock_unlock(&c->stop_lock);

	if (exit_flag)
		pthread_exit(NULL);
}
#else
# define thread_loop_check_exit(s)
#endif /* __APPLE__ */

/*
 * Helper function to terminate the helper threads
 */
static void
stop_and_join_pregen_threads(struct ssh_aes_ctr_ctx_mt *c)
{
	int i;

#ifdef __APPLE__
	/* notify threads that they should exit */
	pthread_rwlock_wrlock(&c->stop_lock);
	c->exit_flag = TRUE;
	pthread_rwlock_unlock(&c->stop_lock);
#endif /* __APPLE__ */

	/* Wake anything parked in pthread_cond_wait() so it rechecks the exit
	 * condition. Without this a parked thread can only be removed by
	 * pthread_cancel(), which leaves the join below blocked if that cancel
	 * is not delivered. */
	for (i = 0; i < c->numkq; i++) {
		pthread_mutex_lock(&c->q[i].lock);
		pthread_cond_broadcast(&c->q[i].cond);
		pthread_mutex_unlock(&c->q[i].lock);
	}

	/* Cancel only the threads that were actually started */
	for (i = 0; i < c->running; i++)
		pthread_cancel(c->tid[i]);

	/* Join each thread, then free its keystream context. Once joined, a
	 * thread can no longer touch its context or the queue locks. */
	for (i = 0; i < c->running; i++) {
		pthread_join(c->tid[i], NULL);
		EVP_CIPHER_CTX_free(c->evp[i]);
		c->evp[i] = NULL;
	}
	c->running = 0;
}

/*
 * The life of a pregen thread:
 *    Find empty keystream queues and fill them using their counter.
 *    When done, update counter for the next fill.
 */
/* previously this used the low level interface which is, sadly,
 * slower than the EVP interface by a long shot. The original ctx (from the
 * body of the code) isn't passed in here but we have the key and the counter
 * which means we should be able to create the exact same ctx and use that to
 * fill the keystream queues. I'm concerned about additional overhead but the
 * additional speed from AESNI should make up for it.  */
/* The above comment was made when I thought I needed to do a new EVP init for
 * each counter increment. Turns out not to be the case -cjr 10/15/21*/

static void *
thread_loop(void *arg)
{
	struct pregen_job *job = arg;
	struct ssh_aes_ctr_ctx_mt *c = job->ctx;
	/* this thread's keystream context, created and keyed by the parent */
	EVP_CIPHER_CTX *evp_ctx = c->evp[job->idx];
	struct kq *q;
	int outlen;

	/*
	 * Handle the special case of startup, one thread must fill
	 * the first KQ then mark it as draining. Lock held throughout.
	 * Thread 0 always does this, so it does not depend on thread ids.
	 */
	if (job->idx == 0) {
		q = &c->q[0];
		pthread_mutex_lock(&q->lock);
		/* if we are in the INIT state then fill the queue */
		if (q->qstate == KQINIT) {
			/* set the initial counter */
			EVP_EncryptInit_ex(evp_ctx, NULL, NULL, NULL, q->ctr);
			/* encrypt a block sized null string (mynull) with the key. This
			 * returns the keystream because xoring the keystream
			 * against null returns the keystream. */
			if (EVP_EncryptUpdate(evp_ctx, q->keys[0], &outlen, mynull,
			    KQLEN * AES_BLOCK_SIZE) != 1)
				fatal("AES-CTR MT keystream generation failed");
			/* Update the aes counter */
			ssh_ctr_add(q->ctr, KQLEN * c->numkq, AES_BLOCK_SIZE);
			/* since this is the first thread set it to draining */
			q->qstate = KQDRAINING;
			pthread_cond_broadcast(&q->cond);
		}
		pthread_mutex_unlock(&q->lock);
	}

	/*
	 * Normal case is to find empty queues and fill them, skipping over
	 * queues already filled by other threads and stopping to wait for
	 * a draining queue to become empty.
	 */
	int qidx;
	for (qidx = 1;; qidx = (qidx + 1) % c->numkq) {
		/* Check if I was cancelled, also checked in cond_wait */
		pthread_testcancel();

		/* Check if we should exit as well */
		thread_loop_check_exit(c);

		/* Lock queue and block if its draining */
		q = &c->q[qidx];
		pthread_mutex_lock(&q->lock);
		pthread_cleanup_push(thread_loop_cleanup, &q->lock);
		while (q->qstate == KQDRAINING || q->qstate == KQINIT) {
			thread_loop_check_exit(c);
			pthread_cond_wait(&q->cond, &q->lock);
		}
		pthread_cleanup_pop(0);

		/* If filling or full, somebody else got it, skip */
		if (q->qstate != KQEMPTY) {
			pthread_mutex_unlock(&q->lock);
			continue;
		}

		/*
		 * Empty, let's fill it.
		 * Queue lock is relinquished while we do this so others
		 * can see that it's being filled.
		 */
		q->qstate = KQFILLING;
		pthread_cond_broadcast(&q->cond);
		pthread_mutex_unlock(&q->lock);

		/* set the initial counter */
		EVP_EncryptInit_ex(evp_ctx, NULL, NULL, NULL, q->ctr);

		/* see coresponding block above for useful comments */
		if (EVP_EncryptUpdate(evp_ctx, q->keys[0], &outlen, mynull,
		    KQLEN * AES_BLOCK_SIZE) != 1)
			fatal("AES-CTR MT keystream generation failed");

		/* Re-lock, mark full and signal consumer */
		pthread_mutex_lock(&q->lock);
		ssh_ctr_add(q->ctr, KQLEN * c->numkq, AES_BLOCK_SIZE);
		q->qstate = KQFULL;
		pthread_cond_broadcast(&q->cond);
		pthread_mutex_unlock(&q->lock);
	}

	return NULL;
}

/* this is where the data is actually enciphered and deciphered */
/* this may also benefit from upgrading to the EVP API */
static int
ssh_aes_ctr(EVP_CIPHER_CTX *ctx, u_char *dest, const u_char *src,
    size_t len)
{
	typedef union {
#ifdef CIPHER_INT128_OK
		__uint128_t *u128;
#endif
		uint64_t *u64;
		uint32_t *u32;
		uint8_t *u8;
		const uint8_t *cu8;
		uintptr_t u;
	} ptrs_t;
	ptrs_t destp, srcp, bufp;
	uintptr_t align;
	struct ssh_aes_ctr_ctx_mt *c;
	struct kq *q, *oldq;
	int ridx;
	u_char *buf;

	if (len == 0)
		return 1;
	if ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == NULL)
		return 0;

	q = &c->q[c->qidx];
	ridx = c->ridx;

	/* src already padded to block multiple */
	srcp.cu8 = src;
	destp.u8 = dest;
	do { /* do until len is 0 */
		buf = q->keys[ridx];
		bufp.u8 = buf;

		/* figure out the alignment on the fly */
#ifdef CIPHER_UNALIGNED_OK
		align = 0;
#else
		align = destp.u | srcp.u | bufp.u;
#endif

		/* xor the src against the key (buf)
		 * different systems can do all 16 bytes at once or
		 * may need to do it in 8 or 4 bytes chunks
		 * worst case is doing it as a loop */
#ifdef CIPHER_INT128_OK
		/* with GCC 13 we have having consistent seg faults
		 * in this section of code. Since this is a critical
		 * code path we are removing this until we have a solution
		 * in place -cjr 02/22/24
		 * TODO: FIX THIS
		 */
		/* if ((align & 0xf) == 0) { */
		/* 	destp.u128[0] = srcp.u128[0] ^ bufp.u128[0]; */
		/* } else */
#endif
		/* this is causing undefined behaviour in sanitizers
		 * this is annoying because it's more efficient
		 * but UB is not something I want to retain */
		/* 64 bits */
		/* if ((align & 0x7) == 0) { */
		/* 	destp.u64[0] = srcp.u64[0] ^ bufp.u64[0]; */
		/* 	destp.u64[1] = srcp.u64[1] ^ bufp.u64[1]; */
		/* /\* 32 bits *\/ */
		/* } else */
		if ((align & 0x3) == 0) {
			destp.u32[0] = srcp.u32[0] ^ bufp.u32[0];
			destp.u32[1] = srcp.u32[1] ^ bufp.u32[1];
			destp.u32[2] = srcp.u32[2] ^ bufp.u32[2];
			destp.u32[3] = srcp.u32[3] ^ bufp.u32[3];
		} else {
			/*1 byte at a time*/
			size_t i;
			for (i = 0; i < AES_BLOCK_SIZE; ++i)
				dest[i] = src[i] ^ buf[i];
		}

		/* inc/decrement the pointers by the block size (16)*/
		destp.u += AES_BLOCK_SIZE;
		srcp.u += AES_BLOCK_SIZE;

		/* Increment read index, switch queues on rollover */
		if ((ridx = (ridx + 1) % KQLEN) == 0) {
			oldq = q;

			/* Mark next queue draining, may need to wait */
			c->qidx = (c->qidx + 1) % c->numkq;
			q = &c->q[c->qidx];
			pthread_mutex_lock(&q->lock);
			while (q->qstate != KQFULL) {
				pthread_cond_wait(&q->cond, &q->lock);
			}
			q->qstate = KQDRAINING;
			pthread_cond_broadcast(&q->cond);
			pthread_mutex_unlock(&q->lock);

			/* Mark consumed queue empty and signal producers */
			pthread_mutex_lock(&oldq->lock);
			oldq->qstate = KQEMPTY;
			pthread_cond_broadcast(&oldq->cond);
			pthread_mutex_unlock(&oldq->lock);
		}
	} while (len -= AES_BLOCK_SIZE);
	c->ridx = ridx;
	return 1;
}

static void
ssh_aes_ctr_get_threads(int *threads, int *numkq)
{
	const char *aes_threads = getenv("SSH_CIPHER_THREADS");
	int t;

	if (aes_threads != NULL && strlen(aes_threads) != 0) {
		t = atoi(aes_threads);
	} else
		t = 1;

	if (t < 1)
		t = 1;
	if (t > MAX_THREADS)
		t = MAX_THREADS;

	*threads = t;
	*numkq = t + 1;
	if (*numkq > MAX_NUMKQ)
		*numkq = MAX_NUMKQ;
}

static int
ssh_aes_ctr_init(EVP_CIPHER_CTX *ctx, const u_char *key, const u_char *iv,
    int enc)
{
	struct ssh_aes_ctr_ctx_mt *c;
	const EVP_CIPHER *cipher = NULL;
	pthread_attr_t attr;
	int i;

	/* set up the initial state of c (our cipher stream struct) */
	if ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == NULL) {
		c = xcalloc(1, sizeof(*c));
		ssh_aes_ctr_get_threads(&c->threads, &c->numkq);

#ifdef __APPLE__
		pthread_rwlock_init(&c->stop_lock, NULL);
		c->exit_flag = FALSE;
#endif /* __APPLE__ */

		c->state = HAVE_NONE;

		/* initialize the mutexs and conditions for each lock in our struct */
		for (i = 0; i < c->numkq; i++) {
			pthread_mutex_init(&c->q[i].lock, NULL);
			pthread_cond_init(&c->q[i].cond, NULL);
		}

		/* attach our struct to the context */
		EVP_CIPHER_CTX_set_app_data(ctx, c);
	}

	/* we are initializing but the current structure already
	   has an IV and key so we want to kill the existing key data
	   and start over. This is important when we need to rekey the data stream */
	if (c->state == (HAVE_KEY | HAVE_IV)) {
		/* tell the pregen threads to exit */
		stop_and_join_pregen_threads(c);

#ifdef __APPLE__
		/* reset the exit flag */
		c->exit_flag = FALSE;
#endif /* __APPLE__ */

		/* Start over getting key & iv */
		c->state = HAVE_NONE;
	}

	/* set the initial key for this key stream queue. The key is copied:
	 * the caller's buffer is not guaranteed to outlive this call. */
	if (key != NULL) {
		int klen = EVP_CIPHER_CTX_key_length(ctx);

		if (klen > (int)sizeof(c->key))
			fatal("AES-CTR MT key of %d bytes is too long", klen);
		memcpy(c->key, key, klen);
		AES_set_encrypt_key(key, klen * 8, &c->aes_key);
		c->keylen = klen * 8;
		c->state |= HAVE_KEY;
	}

	/* set the IV */
	if (iv != NULL) {
		/* init the counter this is just a 16byte uchar */
		memcpy(c->aes_counter, iv, AES_BLOCK_SIZE);
		c->state |= HAVE_IV;
	}

	if (c->state == (HAVE_KEY | HAVE_IV)) {
		switch (c->keylen) {
		case 256:
			cipher = EVP_aes_256_ctr();
			break;
		case 192:
			cipher = EVP_aes_192_ctr();
			break;
		case 128:
			cipher = EVP_aes_128_ctr();
			break;
		default:
			fatal("Invalid key length of %d in AES CTR MT", c->keylen);
		}

		/* Clear queues */
		/* set the first key in the key queue to the current counter */
		memcpy(c->q[0].ctr, c->aes_counter, AES_BLOCK_SIZE);
		/* indicate that it needs to be initialized */
		c->q[0].qstate = KQINIT;
		/* for each of the remaining queues set the first counter to the
		 * counter and then add the size of the queue to the counter */
		for (i = 1; i < c->numkq; i++) {
			memcpy(c->q[i].ctr, c->aes_counter, AES_BLOCK_SIZE);
			ssh_ctr_add(c->q[i].ctr, i * KQLEN, AES_BLOCK_SIZE);
			c->q[i].qstate = KQEMPTY;
		}
		c->qidx = 0;
		c->ridx = 0;
		c->struct_id = global_struct_id++;

		/* Start threads with enough stack (see functions version) */
#define STACK_SIZE (1024 * 1024)
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, STACK_SIZE);

		/* Each thread gets its keystream context here, keyed before the
		 * thread exists, so a thread never has to create or key one. */
		for (i = 0; i < c->threads; i++) {
			c->evp[i] = EVP_CIPHER_CTX_new();
			if (c->evp[i] == NULL ||
			    EVP_EncryptInit_ex(c->evp[i], cipher, NULL, c->key, NULL) != 1)
				fatal("AES-CTR MT could not set up keystream context");

			c->job[i].ctx = c;
			c->job[i].idx = i;
			c->id[i] = i;
			if (pthread_create(&c->tid[i], &attr, thread_loop, &c->job[i]) != 0)
				fatal("AES-CTR MT Could not create thread in %s", __func__);
			c->running++;
		}
		pthread_attr_destroy(&attr);

		pthread_mutex_lock(&c->q[0].lock);
		// wait for all of the threads to be initialized
		while (c->q[0].qstate == KQINIT)
			pthread_cond_wait(&c->q[0].cond, &c->q[0].lock);
		pthread_mutex_unlock(&c->q[0].lock);
	}
	return 1;
}

static int
ssh_aes_ctr_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct ssh_aes_ctr_ctx_mt *c;
	int i;

	if ((c = EVP_CIPHER_CTX_get_app_data(ctx)) != NULL) {
		stop_and_join_pregen_threads(c);

		/* All threads are joined, so nothing can use the locks now */
		for (i = 0; i < c->numkq; i++) {
			pthread_mutex_destroy(&c->q[i].lock);
			pthread_cond_destroy(&c->q[i].cond);
		}
#ifdef __APPLE__
		pthread_rwlock_destroy(&c->stop_lock);
#endif /* __APPLE__ */

		explicit_bzero(c, sizeof(*c));
		free(c);
		EVP_CIPHER_CTX_set_app_data(ctx, NULL);
	}
	return 1;
}

/* <friedl> */
const EVP_CIPHER *
evp_aes_ctr_mt(void)
{
	static EVP_CIPHER *aes_ctr;
	aes_ctr = EVP_CIPHER_meth_new(NID_undef, 16/*block*/, 16/*key*/);
	EVP_CIPHER_meth_set_iv_length(aes_ctr, AES_BLOCK_SIZE);
	EVP_CIPHER_meth_set_init(aes_ctr, ssh_aes_ctr_init);
	EVP_CIPHER_meth_set_cleanup(aes_ctr, ssh_aes_ctr_cleanup);
	EVP_CIPHER_meth_set_do_cipher(aes_ctr, ssh_aes_ctr);
#  ifndef SSH_OLD_EVP
	EVP_CIPHER_meth_set_flags(aes_ctr, EVP_CIPH_CBC_MODE
				      | EVP_CIPH_VARIABLE_LENGTH
				      | EVP_CIPH_ALWAYS_CALL_INIT
				      | EVP_CIPH_CUSTOM_IV);
#  endif /*SSH_OLD_EVP*/
	return aes_ctr;
}
#endif /* OSSL Check */
