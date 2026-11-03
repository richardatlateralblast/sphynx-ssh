/*
 * OpenSSH Multi-threaded AES-CTR Cipher Provider for OpenSSL 3
 *
 * Author: Benjamin Bennett <ben@psc.edu>
 * Author: Mike Tasota <tasota@gmail.com>
 * Author: Chris Rapier <rapier@psc.edu>
 * Copyright (c) 2008-2022 Pittsburgh Supercomputing Center. All rights reserved.
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

/* only for systems with OSSL 3 */
#ifdef WITH_OPENSSL3
#include <stdarg.h>
#include <string.h>
#include <openssl/evp.h>
#include "xmalloc.h"
#include <unistd.h>
#include "cipher-ctr-mt-functions.h"
#include "log.h"

/* for provider error struct */
#include "ossl3-provider-err.h"
#include "num.h"

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
/* The number of pregen threads and keystream queues is chosen for each
 * cipher context by get_thread_count() (SSH_CIPHER_THREADS). The limits
 * are MAX_THREADS and MAX_NUMKQ in cipher-ctr-mt-functions.h. */
/*-------------------- END TUNABLES --------------------*/

/* globals */
/* how we increment the id the structs we create */
long unsigned int global_struct_id = 0;

/* An all-zero block of input for the keystream generator. It is only read,
 * so it can be static instead of a 512KB array on each thread's stack. */
static const u_char mynull[KQLEN * AES_BLOCK_SIZE];

/* private functions */

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

/* Check if we should exit, we are doing both cancel and exit condition
 * since threads can fail to notice that they have been cancelled: on OSX
 * natively, and on any platform when running under valgrind, whose
 * scheduler does not deliver a cancel to a thread parked in
 * pthread_cond_wait(). We want a backup to make sure that we won't hang
 * when the main process join()-s the cancelled thread.
 */
static void
thread_loop_check_exit(struct aes_mt_ctx_st *aes_mt_ctx)
{
	int exit_flag;

	pthread_rwlock_rdlock(&aes_mt_ctx->stop_lock);
	exit_flag = aes_mt_ctx->exit_flag;
	pthread_rwlock_unlock(&aes_mt_ctx->stop_lock);

	if (exit_flag)
		pthread_exit(NULL);
}

/*
 * Helper function to terminate the helper threads
 */
static void
stop_and_join_pregen_threads(struct aes_mt_ctx_st *aes_mt_ctx)
{
	int i;

	/* notify threads that they should exit */
	pthread_rwlock_wrlock(&aes_mt_ctx->stop_lock);
	aes_mt_ctx->exit_flag = 1;
	pthread_rwlock_unlock(&aes_mt_ctx->stop_lock);

	/*
	 * Wake anything parked in pthread_cond_wait() so that it rechecks
	 * the exit flag and leaves via thread_loop_check_exit(). Without
	 * this a parked thread can only be removed by pthread_cancel(),
	 * which leaves the join below blocked indefinitely whenever that
	 * cancel is not delivered.
	 */
	for (i = 0; i < aes_mt_ctx->numkq; i++) {
		pthread_mutex_lock(&aes_mt_ctx->q[i].lock);
		pthread_cond_broadcast(&aes_mt_ctx->q[i].cond);
		pthread_mutex_unlock(&aes_mt_ctx->q[i].lock);
	}

	/* Cancel only the threads that were actually started */
	for (i = 0; i < aes_mt_ctx->running; i++) {
		debug_f("Canceled %lu (%lu,%d)", aes_mt_ctx->tid[i],
		    aes_mt_ctx->struct_id, aes_mt_ctx->id[i]);
		pthread_cancel(aes_mt_ctx->tid[i]);
	}

	/*
	 * Join each thread and then free its keystream context. A thread
	 * that has been joined can no longer touch its context or the queue
	 * locks, so this order is safe.
	 */
	for (i = 0; i < aes_mt_ctx->running; i++) {
		debug_f("Joining %lu (%lu, %d)", aes_mt_ctx->tid[i],
		    aes_mt_ctx->struct_id, aes_mt_ctx->id[i]);
		pthread_join(aes_mt_ctx->tid[i], NULL);
		EVP_CIPHER_CTX_free(aes_mt_ctx->evp[i]);
		aes_mt_ctx->evp[i] = NULL;
	}
	aes_mt_ctx->running = 0;
}

/* determine the number of threads and queues to use for one context
 * Testing indicates that in most all situations the optimal number of
 * threads is 1 meaning 1 for inbound and 1 for outbound. The optimal
 * queue count has also been determined to be thread_count + 1.
 * The values are returned to the caller rather than stored in globals,
 * so each context keeps the numbers it started with. */
static void
get_thread_count(int *threads, int *numkq)
{
	const char *aes_threads = getenv("SSH_CIPHER_THREADS");
	int t;

	if (aes_threads != NULL && strlen(aes_threads) != 0) {
		debug_f("SSH thread count is %s", aes_threads);
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

	debug_f("Starting %d threads and %d queues", *threads, *numkq);
}


/*
 * The life of a pregen thread:
 *    Find empty keystream queues and fill them using their counter.
 *    When done, update counter for the next fill.
 */
static void *
thread_loop(void *arg)
{
	struct pregen_job *job = arg;
	struct aes_mt_ctx_st *aes_mt_ctx = job->ctx;
	/* this thread's keystream context, created and keyed by the parent */
	EVP_CIPHER_CTX *evp_ctx = aes_mt_ctx->evp[job->idx];
	struct kq *q;
	int outlen;

	/*
	 * Handle the special case of startup, one thread must fill
	 * the first KQ then mark it as draining. Lock held throughout.
	 * Thread 0 always does this, so it does not depend on thread ids.
	 */
	if (job->idx == 0) {
		/* get the first element of the key queue struct */
		q = &aes_mt_ctx->q[0];
		pthread_mutex_lock(&q->lock);
		/* if we are in the INIT state then fill the queue */
		if (q->qstate == KQINIT) {
			/* set the initial counter */
			EVP_EncryptInit_ex(evp_ctx, NULL, NULL, NULL, q->ctr);
			/* encypher a block sized null string (mynull) with the key. This
			 * returns the keystream because xoring the keystream
			 * against null returns the keystream. Store that in the appropriate queue */
			if (EVP_EncryptUpdate(evp_ctx, q->keys[0], &outlen, mynull,
			    KQLEN * AES_BLOCK_SIZE) != 1)
				fatal("AES-CTR MT keystream generation failed");
			/* Update the aes counter */
			ssh_ctr_add(q->ctr, KQLEN * aes_mt_ctx->numkq, AES_BLOCK_SIZE);
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
	 *
	 * Multiple threads may be waiting on a draining queue and awoken
	 * when empty. The first thread to wake will mark it as filling,
	 * others will move on to fill, skip, or wait on the next queue.
	 * We init qidx here because if we do it at the top of the function
	 * we get a warning about it possibly being clobbered. The exact reason
	 * doesn't make a lot of sense but it has to happen after the
	 * first pthread_rwlock_rdlock(). Might have something to do with
	 * incorrect compiler optimizations.
	 */
	int qidx;
	for (qidx = 1;; qidx = (qidx + 1) % aes_mt_ctx->numkq) {
		/* Check if I was cancelled, also checked in cond_wait */
		pthread_testcancel();

		/* Check if we should exit as well */
		thread_loop_check_exit(aes_mt_ctx);

		/* Lock queue and block if its draining */
		q = &aes_mt_ctx->q[qidx];
		pthread_mutex_lock(&q->lock);
		pthread_cleanup_push(thread_loop_cleanup, &q->lock);
		while (q->qstate == KQDRAINING || q->qstate == KQINIT) {
			thread_loop_check_exit(aes_mt_ctx);
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
		ssh_ctr_add(q->ctr, KQLEN * aes_mt_ctx->numkq, AES_BLOCK_SIZE);
		q->qstate = KQFULL;
		pthread_cond_broadcast(&q->cond);
		pthread_mutex_unlock(&q->lock);
	}

	return NULL;
}


/* Our version of the EVP functions
 * these are public as they are used by the provider */

/* instantiate the cipher context.
 * in this we create the EVP ctx and the AES ctx, setup the AES ctx
 * initialize the EVP and then attach the AES ctx to the EVP ctx.
 * parameters: provider context
 * returns: EVP context
 */
/* Shared constructor. The three public constructors differ only in the
 * cipher they set, so they all call this. The thread and queue counts are
 * read here, once, and stored in the context. */
static void *
aes_mt_newctx(void *provctx, const EVP_CIPHER *cipher)
{
	struct aes_mt_ctx_st *aes_mt_ctx;
	EVP_CIPHER_CTX *evp_ctx;
	int i;

	aes_mt_ctx = calloc(1, sizeof(*aes_mt_ctx));
	evp_ctx = EVP_CIPHER_CTX_new();
	if (aes_mt_ctx == NULL || evp_ctx == NULL) {
		free(aes_mt_ctx);
		EVP_CIPHER_CTX_free(evp_ctx);
		return NULL;
	}

	get_thread_count(&aes_mt_ctx->threads, &aes_mt_ctx->numkq);
	pthread_rwlock_init(&aes_mt_ctx->stop_lock, NULL);
	aes_mt_ctx->exit_flag = 0;
	aes_mt_ctx->running = 0;

	aes_mt_ctx->state = HAVE_NONE;

	/* initialize the mutexs and conditions for each lock in our struct */
	for (i = 0; i < aes_mt_ctx->numkq; i++) {
		pthread_mutex_init(&aes_mt_ctx->q[i].lock, NULL);
		pthread_cond_init(&aes_mt_ctx->q[i].cond, NULL);
	}
	aes_mt_ctx->provctx = provctx;
	EVP_CipherInit(evp_ctx, cipher, NULL, NULL, 0);
	EVP_CIPHER_CTX_set_app_data(evp_ctx, aes_mt_ctx);
	return evp_ctx;
}

/* honestly the way this works makes me think that there has to be
 * a better way of doing this however, I've yet to find one that doesn't
 * involve more madness. I think that's mostly becase I don't understand
 * how params work properly. I feel like I shoudl be able to use them
 * to specify the key length but... also, I'd think I'd be able to
 * set aes_mt_ctx_st->keylen to the keylength but that doesn't seem to
 * work either. That said, this does work even if it's a bit clunky.
 * -cjr 09/08/2022 */
void *aes_mt_newctx_256(void *provctx)
{
	return aes_mt_newctx(provctx, EVP_aes_256_ctr());
}

void *aes_mt_newctx_192(void *provctx)
{
	return aes_mt_newctx(provctx, EVP_aes_192_ctr());
}

void *aes_mt_newctx_128(void *provctx)
{
	return aes_mt_newctx(provctx, EVP_aes_128_ctr());
}

/* this function expects a void but we need the actual context
 * to get the app_data.
 */
void aes_mt_freectx(void *vevp_ctx)
{
	EVP_CIPHER_CTX *evp_ctx = vevp_ctx;
	struct aes_mt_ctx_st *aes_mt_ctx;
	int i;

	if ((aes_mt_ctx = EVP_CIPHER_CTX_get_app_data(evp_ctx)) != NULL) {
		stop_and_join_pregen_threads(aes_mt_ctx);

		/* All threads are joined, so nothing can use the locks now */
		for (i = 0; i < aes_mt_ctx->numkq; i++) {
			pthread_mutex_destroy(&aes_mt_ctx->q[i].lock);
			pthread_cond_destroy(&aes_mt_ctx->q[i].cond);
		}
		pthread_rwlock_destroy(&aes_mt_ctx->stop_lock);

		explicit_bzero(aes_mt_ctx, sizeof(*aes_mt_ctx));
		free(aes_mt_ctx);
		EVP_CIPHER_CTX_set_app_data(evp_ctx, NULL);
	}
	EVP_CIPHER_CTX_free(evp_ctx);
}

/* this function takes the EVP context, gets the AES context
 * and starts the various threads we need */
int aes_mt_start_threads(void *vevp_ctx, const u_char *key,
			 size_t keylen, const u_char *iv,
			 size_t ivlen, const OSSL_PARAM *ossl_params)
{
	EVP_CIPHER_CTX *evp_ctx = vevp_ctx;
	struct aes_mt_ctx_st *aes_mt_ctx;
	const EVP_CIPHER *cipher = NULL;
	pthread_attr_t attr;
	int i;

	/* get the initial state of aes_mt_ctx (our cipher stream struct) */
	if ((aes_mt_ctx = EVP_CIPHER_CTX_get_app_data(evp_ctx)) == NULL) {
		fatal("Missing AES MT context data!");
	}

	/* we are initializing but the current structure already
	 * has an IV and key so we want to kill the existing key data
	 * and start over. This is important when we need to rekey the data stream */
	if (aes_mt_ctx->state == (HAVE_KEY | HAVE_IV)) {
		/* tell the pregen threads to exit */
		stop_and_join_pregen_threads(aes_mt_ctx);

		/* reset the exit flag */
		aes_mt_ctx->exit_flag = 0;

		/* Start over getting key & iv */
		aes_mt_ctx->state = HAVE_NONE;
	}

	/* set the initial key for this key stream queue. The key is copied:
	 * the caller's buffer is not guaranteed to outlive this call. */
	if (key != NULL) {
		size_t klen = EVP_CIPHER_CTX_key_length(evp_ctx);

		if (klen > sizeof(aes_mt_ctx->key))
			fatal("AES-CTR MT key of %zu bytes is too long", klen);
		memcpy(aes_mt_ctx->key, key, klen);
		aes_mt_ctx->keylen = klen * 8;
		aes_mt_ctx->state |= HAVE_KEY;
	}

	/* set the IV */
	if (iv != NULL) {
		/* init the counter this is just a 16byte uchar */
		memcpy(aes_mt_ctx->aes_counter, iv, AES_BLOCK_SIZE);
		aes_mt_ctx->state |= HAVE_IV;
	}

	if (aes_mt_ctx->state == (HAVE_KEY | HAVE_IV)) {
		switch (aes_mt_ctx->keylen) {
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
			fatal("Invalid key length of %d in AES CTR MT", aes_mt_ctx->keylen);
		}

		/* Clear queues */
		/* set the first key in the key queue to the current counter */
		memcpy(aes_mt_ctx->q[0].ctr, aes_mt_ctx->aes_counter, AES_BLOCK_SIZE);
		/* indicate that it needs to be initialized */
		aes_mt_ctx->q[0].qstate = KQINIT;
		/* for each of the remaining queues set the first counter to the
		 * counter and then add the size of the queue to the counter */
		for (i = 1; i < aes_mt_ctx->numkq; i++) {
			memcpy(aes_mt_ctx->q[i].ctr, aes_mt_ctx->aes_counter, AES_BLOCK_SIZE);
			ssh_ctr_add(aes_mt_ctx->q[i].ctr, i * KQLEN, AES_BLOCK_SIZE);
			aes_mt_ctx->q[i].qstate = KQEMPTY;
		}
		aes_mt_ctx->qidx = 0;
		aes_mt_ctx->ridx = 0;
		aes_mt_ctx->struct_id = global_struct_id++;

		/* Make sure we have enough stack space (under alpine)
		 * and aren't using more than we need (linux). This can be as low as
		 * 512KB but that's a minimum. 1024KB gives us a little headroom if we
		 * need it */
#define STACK_SIZE (1024 * 1024)
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, STACK_SIZE);

		/* Each thread gets its keystream context here, keyed before the
		 * thread exists, so a thread never has to create or key one. */
		for (i = 0; i < aes_mt_ctx->threads; i++) {
			aes_mt_ctx->evp[i] = EVP_CIPHER_CTX_new();
			if (aes_mt_ctx->evp[i] == NULL ||
			    EVP_EncryptInit_ex(aes_mt_ctx->evp[i], cipher, NULL,
			    aes_mt_ctx->key, NULL) != 1)
				fatal("AES-CTR MT could not set up keystream context");

			aes_mt_ctx->job[i].ctx = aes_mt_ctx;
			aes_mt_ctx->job[i].idx = i;
			aes_mt_ctx->id[i] = i;
			if (pthread_create(&aes_mt_ctx->tid[i], &attr, thread_loop,
			    &aes_mt_ctx->job[i]) != 0)
				fatal("AES-CTR MT Could not create thread in %s", __func__);
			aes_mt_ctx->running++;
			debug_f("AES-CTR MT spawned a thread with id %lu (%lu, %d)",
			    aes_mt_ctx->tid[i], aes_mt_ctx->struct_id, aes_mt_ctx->id[i]);
		}
		pthread_attr_destroy(&attr);

		pthread_mutex_lock(&aes_mt_ctx->q[0].lock);
		// wait for all of the threads to be initialized
		while (aes_mt_ctx->q[0].qstate == KQINIT)
			pthread_cond_wait(&aes_mt_ctx->q[0].cond, &aes_mt_ctx->q[0].lock);
		pthread_mutex_unlock(&aes_mt_ctx->q[0].lock);
	}
	return 1;
}

/* this should correspond to ssh_aes_ctr
 * OSSL_CORE_MAKE_FUNC(int, cipher_cipher,
 *                     (void *cctx,
 *                     unsigned char *out, size_t *outl, size_t outsize,
 *                     const unsigned char *in, size_t inl))
 */

int aes_mt_do_cipher(void *vevp_ctx,
			    u_char *dest, size_t *destlen, size_t destsize,
			    const u_char *src, size_t len)
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
	struct aes_mt_ctx_st *aes_mt_ctx;
	struct kq *q, *oldq;
	int ridx;
	u_char *buf;
	EVP_CIPHER_CTX *evp_ctx = vevp_ctx;
	uint64_t src_a, key_a;
	
	if (len == 0)
		return 1;

	if ((aes_mt_ctx = EVP_CIPHER_CTX_get_app_data(evp_ctx)) == NULL)
		return 0;

	q = &aes_mt_ctx->q[aes_mt_ctx->qidx];
	ridx = aes_mt_ctx->ridx;

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
		/* 64 bits */
		/* this is causing undefined behaviour in sanitizers
		 * this is annoying because it's more efficient
		 * but UB is not something I want to retain */
		if ((align & 0x7) == 0) {
			/* this should resolve the strict aliasing UB
			 * and the performance doesn't seem to change much
			 * but the memcpys are killing me 3-5-26 cjr*/
			memcpy(&src_a, &srcp.u64[0], sizeof(uint64_t));
			memcpy(&key_a, &bufp.u64[0], sizeof(uint64_t));
			destp.u64[0] = src_a ^ key_a;
			memcpy(&src_a, &srcp.u64[1], sizeof(uint64_t));
			memcpy(&key_a, &bufp.u64[1], sizeof(uint64_t));
			destp.u64[1] = src_a ^ key_a;
			/* destp.u64[0] = srcp.u64[0] ^ bufp.u64[0]; */
			/* destp.u64[1] = srcp.u64[1] ^ bufp.u64[1]; */
                /* 32 bits */
		} else
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
			aes_mt_ctx->qidx = (aes_mt_ctx->qidx + 1) % aes_mt_ctx->numkq;
			q = &aes_mt_ctx->q[aes_mt_ctx->qidx];
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
	aes_mt_ctx->ridx = ridx;
	return 1;
}

#endif /*WITH_OPENSSL3*/
