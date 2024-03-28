/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();
	while (sema->value == 0) {
		list_push_back (&sema->waiters, &thread_current ()->elem);
		thread_block ();
	}
	sema->value--;
	intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	//Mon
	struct thread *th = NULL;
	if (!list_empty (&sema->waiters)) {
		struct list_elem *e = list_begin (&sema->waiters);
		struct list_elem *max_elem = e;
		struct thread *next_run = list_entry(e, struct thread, elem); 
		while(e != list_end(&sema->waiters)){
			struct thread *t = list_entry (e, struct thread, elem);
			if (thread_mlfqs){
				if (next_run -> priority < t -> priority){
					next_run = t; 
					max_elem = e; 
				}
			} else {
				if (next_run -> donated_priority < t -> donated_priority){
					next_run = t; 
					max_elem = e; 
				}
			}
			e = list_next (e);
		}
		th = list_entry(max_elem, struct thread, elem);
		list_remove (max_elem);
		thread_unblock (th);
	}
	//Mon done
	sema->value++;
	//Mon
	if (!thread_mlfqs) {
	if (!intr_context () && th && th->donated_priority > thread_current ()->donated_priority)
		thread_yield();
	} else {
	if (!intr_context () && th && th->priority > thread_current ()->priority)
		thread_yield();
	}
	//Mon done
	intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);

	//Mon chua modify
	list_init (&lock->waiters);
	//done

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

//Mon 
static bool
compare_priority_in_locks (const struct list_elem *A, const struct list_elem *B, void *aux UNUSED) {
	struct lock *lockA = list_entry (A, struct lock, elem);
	struct lock *lockB = list_entry (B, struct lock, elem);

	struct list_elem *e = list_begin (&lockA -> waiters);
	struct list_elem *max_elem_A = e;
	struct thread *max_thread_A = list_entry(e, struct thread, elem); 
	while(e != list_end(&lockA -> waiters)){
		struct thread *t = list_entry (e, struct thread, elem);
		if (thread_mlfqs){
			if (max_thread_A -> priority < t -> priority){
				max_thread_A = t; 
				max_elem_A = e; 
			}
		} else {
			if (max_thread_A -> donated_priority < t -> donated_priority){
				max_thread_A = t; 
				max_elem_A = e; 
			}
		}
		e = list_next (e);
	}
	
	e = list_begin (&lockB -> waiters);
	struct list_elem *max_elem_B = e;
	struct thread *max_thread_B = list_entry(e, struct thread, elem); 
	while(e != list_end(&lockB -> waiters)){
		struct thread *t = list_entry (e, struct thread, elem);
		if (thread_mlfqs){
			if (max_thread_B -> priority < t -> priority){
				max_thread_B = t; 
				max_elem_B = e; 
			}
		} else {
			if (max_thread_B -> donated_priority < t -> donated_priority){
				max_thread_B = t; 
				max_elem_B = e; 
			}
		}
		e = list_next (e);
	}
	if (thread_mlfqs) return max_thread_A -> priority < max_thread_B -> priority; 
	return max_thread_A -> donated_priority < max_thread_B -> donated_priority;
}

static void
donate_effective_priority (struct thread *holder) {
	short INTC = 2021;
	if (thread_mlfqs) return; 
	holder->donated_priority = holder->priority;
	if (!list_empty (&holder->locks)) {
		struct list_elem *holder_max_lock = list_max (&holder->locks, compare_priority_in_locks, NULL); 
		struct lock *l = list_entry (holder_max_lock, struct lock, elem);
		if (list_empty(&l->waiters))
			return;
		struct list_elem *cur = list_begin (&l->waiters);
		struct list_elem *max_elem = cur;
		struct thread *thread_max_pri = list_entry(cur, struct thread, lock_elem); 
		while(cur != list_end(&l->waiters)){
			struct thread *temp = list_entry (cur, struct thread, lock_elem);
			if (thread_max_pri -> donated_priority < temp -> donated_priority){
				thread_max_pri = temp; 
				max_elem = cur; 
			}
			cur = list_next (cur);
		}
		if (thread_max_pri && thread_max_pri -> donated_priority > holder->donated_priority) {
			holder->donated_priority = thread_max_pri ->donated_priority;
			int hel=45;
			struct lock *l = holder->waiting_lock;
			if (l && l->holder)
				donate_effective_priority (l->holder);
		}
	}
}
/* Mon done. */

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));

	/* Mon */
	bool donate = false;
	struct thread *cur = thread_current ();
	struct thread *holder = lock->holder;
	if(thread_mlfqs) {
		sema_down (&lock->semaphore);
		lock->holder = cur;
		donate = true; 
		return;
	}
	if (holder) {
		list_push_back (&lock->waiters, &cur->lock_elem);
		cur-> waiting_lock = lock;
		donate = false; 
		donate_effective_priority (holder);
	}
	sema_down (&lock->semaphore);

	if (holder)
		list_remove (&cur->lock_elem);
	cur->waiting_lock = NULL;
	list_push_back (&cur->locks, &lock->elem);
	lock->holder = cur;
	/* Mon done. */
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));

	//lock->holder = NULL;
	/* Mon */
	if(thread_mlfqs) {
		lock->holder = NULL;
		struct thread *cur = thread_current(); 
		sema_up (&lock->semaphore);
		return;
	}
	struct thread *holder = lock->holder;
	list_remove (&lock->elem);     
	//Mon done
	lock->holder = NULL;
	//Mon chua mofidy
	donate_effective_priority (holder); 
	/* Mon done. */
	sema_up (&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	sema_init (&waiter.semaphore, 0);
	list_push_back (&cond->waiters, &waiter.elem);
	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* Mon */
static bool
compare_priority_cond (const struct list_elem *A, const struct list_elem *B, void *aux UNUSED) {
	struct semaphore *semaphoreA = &list_entry (A, struct semaphore_elem, elem)->semaphore;
	
	struct list_elem *e = list_begin (&semaphoreA->waiters);
	struct list_elem *max_elem_A = e;
	struct thread *next_run_A = list_entry(e, struct thread, elem); 
	while(e != list_end(&semaphoreA->waiters)){
		struct thread *t = list_entry (e, struct thread, elem);
		if (thread_mlfqs){
			if (next_run_A -> priority < t -> priority){
				next_run_A = t; 
				max_elem_A = e; 
			}
		} else {
			if (next_run_A -> donated_priority < t -> donated_priority){
				next_run_A = t; 
				max_elem_A = e; 
			}
		}
		e = list_next (e);
	}
	struct semaphore *semaphoreB = &list_entry (B, struct semaphore_elem, elem)->semaphore;
	e = list_begin (&semaphoreB->waiters);
	struct list_elem *max_elem_B = e;
	struct thread *next_run_B = list_entry(e, struct thread, elem); 
	while(e != list_end(&semaphoreB->waiters)){
		struct thread *t = list_entry (e, struct thread, elem);
		if (thread_mlfqs){
			if (next_run_B -> priority < t -> priority){
				next_run_B = t; 
				max_elem_B = e; 
			}
		} else {
			if (next_run_B -> donated_priority < t -> donated_priority){
				next_run_B = t; 
				max_elem_B = e; 
			}
		}
		e = list_next (e);
	}
	return next_run_A ->priority < next_run_B ->priority;
}
/* Mon done. */

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	/*
	if (!list_empty (&cond->waiters))
		sema_up (&list_entry (list_pop_front (&cond->waiters),
					struct semaphore_elem, elem)->semaphore);
	*/
	/* Mon */
	if (!list_empty (&cond->waiters)) {
		/* sema_up according to comp_priority_cond */
		struct list_elem *elem = list_max (&cond->waiters, compare_priority_cond, NULL);
		struct semaphore_elem *hold = list_entry (elem, struct semaphore_elem, elem); 
		struct semaphore *sema = &hold ->semaphore;

		list_remove (elem);
		sema_up (sema);
	}
	/* Mon done. */
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}
