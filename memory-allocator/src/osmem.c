// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <unistd.h>
#include "osmem.h"
#include "block_meta.h"
#define ALIGNMENT           8
#define ALIGN(size)         (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define METADATA_SIZE		(sizeof(struct block_meta))
#define MMAP_THRESHOLD		(128 * 1024)
#define MOCK_PREALLOC		(MMAP_THRESHOLD - METADATA_SIZE)

struct block_meta *BM_header_SBRK;
struct block_meta *BM_header_MMAP;

void SBRK_Coalesce_Blocks(void)
{
	for (struct block_meta *p = BM_header_SBRK; p != NULL; p = p)
		if (p->status == STATUS_FREE && p->next && p->next->status == STATUS_FREE) {
			p->size = p->size + METADATA_SIZE + p->next->size;
			p->next = p->next->next;
			if (p->next)
				p->next->prev = p;
		} else {
			p = p->next;
		}
}

void SBRK_Find_Best_Block(struct block_meta **current_BM_ptr, size_t BM_size)
{
	// Maximum size of a BM allocated with SBRK is MMAP_THRESHOLD
	size_t min_BM_size = MMAP_THRESHOLD;
	// min_BM_size -> minimum size of The Best Block
	for (struct block_meta *p = BM_header_SBRK; p != NULL; p = p->next)
		if (p->status == STATUS_FREE && p->size >= BM_size && p->size < min_BM_size) {
			min_BM_size = p->size;
			(*current_BM_ptr) = p;
		}
}

void SBRK_Split_Block(struct block_meta *current_BM_ptr, size_t BM_size)
{
	struct block_meta *new_BM_ptr = NULL;
	// new_BM_ptr -> The New Block
	new_BM_ptr = (void *)current_BM_ptr + BM_size + METADATA_SIZE;
	new_BM_ptr->size = current_BM_ptr->size - (BM_size + METADATA_SIZE);
	new_BM_ptr->status = STATUS_FREE;
	new_BM_ptr->prev = current_BM_ptr;
	new_BM_ptr->next = current_BM_ptr->next;
	current_BM_ptr->size = BM_size;
	if (current_BM_ptr->next)
		new_BM_ptr->next->prev = new_BM_ptr;
	current_BM_ptr->next = new_BM_ptr;
}

void SBRK_Extend_Block(struct block_meta *current_BM_ptr, size_t BM_size)
{
	struct block_meta *extend_current_BM_ptr = NULL;
	// extend_current_BM_ptr -> The Extension of The Current Block
	extend_current_BM_ptr = sbrk(BM_size - current_BM_ptr->size);
	DIE(extend_current_BM_ptr == ((void *)-1), "SBRK: error in heap extend");
	current_BM_ptr->size = BM_size;
	current_BM_ptr->status = STATUS_ALLOC;
}

void *SBRK_Alloc_New_Block(struct block_meta *current_BM_ptr, size_t BM_size)
{
	struct block_meta *new_BM_ptr = NULL;
	// new_BM_ptr -> The New Block
	new_BM_ptr = sbrk(METADATA_SIZE + BM_size);
	DIE(new_BM_ptr == ((void *)-1), "SBRK: error in heap alloc");
	new_BM_ptr->size = BM_size;
	new_BM_ptr->status = STATUS_ALLOC;
	new_BM_ptr->prev = current_BM_ptr;
	new_BM_ptr->next = NULL;
	current_BM_ptr->next = new_BM_ptr;
	return (void *)new_BM_ptr;
}

void *SBRK_Allocation(struct block_meta *current_BM_ptr, size_t BM_size)
{
	// Heap Preallocation
	if (!BM_header_SBRK) {
		BM_header_SBRK = sbrk(METADATA_SIZE + MOCK_PREALLOC);
		DIE(BM_header_SBRK == ((void *)-1), "SBRK: error in heap prealloc");
		BM_header_SBRK->size = MOCK_PREALLOC;
		BM_header_SBRK->status = STATUS_FREE;
		BM_header_SBRK->prev = NULL;
		BM_header_SBRK->next = NULL;
	}
	SBRK_Coalesce_Blocks();
	SBRK_Find_Best_Block(&current_BM_ptr, BM_size);
	if (current_BM_ptr) {
		current_BM_ptr->status = STATUS_ALLOC;
		if (current_BM_ptr->size >= BM_size + METADATA_SIZE + ALIGNMENT)
			SBRK_Split_Block(current_BM_ptr, BM_size);
		return (void *)current_BM_ptr + METADATA_SIZE;
	}
	current_BM_ptr = BM_header_SBRK;
	while (current_BM_ptr->next)
		current_BM_ptr = current_BM_ptr->next;
	if (current_BM_ptr->status == STATUS_FREE) {
		SBRK_Extend_Block(current_BM_ptr, BM_size);
		return (void *)current_BM_ptr + METADATA_SIZE;
	}
	return SBRK_Alloc_New_Block(current_BM_ptr, BM_size) + METADATA_SIZE;
}

void MMAP_Coalesce_Blocks(void)
{
	for (struct block_meta *p = BM_header_MMAP; p != NULL; p = p)
		if (p->status == STATUS_FREE && p->next && p->next->status == STATUS_FREE) {
			p->size = p->size + METADATA_SIZE + p->next->size;
			p->next = p->next->next;
			if (p->next)
				p->next->prev = p;
		} else {
			p = p->next;
		}
}

void *MMAP_Alloc_New_Block(struct block_meta *current_BM_ptr, size_t BM_size)
{
	struct block_meta *new_BM_ptr = NULL;
	// new_BM_ptr -> The New Block
	new_BM_ptr = mmap(NULL, BM_size + METADATA_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	DIE(new_BM_ptr == MAP_FAILED, "MMAP: error in heap alloc");
	new_BM_ptr->size = BM_size;
	new_BM_ptr->status = STATUS_MAPPED;
	new_BM_ptr->prev = current_BM_ptr;
	new_BM_ptr->next = NULL;
	current_BM_ptr->next = new_BM_ptr;
	return (void *)new_BM_ptr;
}

void *MMAP_Allocation(struct block_meta *current_BM_ptr, size_t BM_size)
{
	// MMAP initial allocation
	if (!BM_header_MMAP) {
		BM_header_MMAP = mmap(NULL, BM_size + METADATA_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		DIE(BM_header_MMAP == MAP_FAILED, "MMAP: error in heap alloc");
		BM_header_MMAP->size = BM_size;
		BM_header_MMAP->status = STATUS_MAPPED;
		BM_header_MMAP->prev = NULL;
		BM_header_MMAP->next = NULL;
		return (void *)BM_header_MMAP + METADATA_SIZE;
	}
	MMAP_Coalesce_Blocks();
	current_BM_ptr = BM_header_MMAP;
	while (current_BM_ptr->next)
		current_BM_ptr = current_BM_ptr->next;
	return MMAP_Alloc_New_Block(current_BM_ptr, BM_size) + METADATA_SIZE;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	struct block_meta *current_BM_ptr = NULL;
	size_t BM_size = ALIGN(size);

	if (BM_size == 0)
		return NULL;
	if (METADATA_SIZE + BM_size < MMAP_THRESHOLD)
		return SBRK_Allocation(current_BM_ptr, BM_size);
	return MMAP_Allocation(current_BM_ptr, BM_size);
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (!ptr)
		return;
	for (struct block_meta *p = BM_header_SBRK; p != NULL; p = p->next)
		if (p->status == STATUS_ALLOC && ((void *)p + METADATA_SIZE) == ptr) {
			p->status = STATUS_FREE;
			break;
		}
	for (struct block_meta *p = BM_header_MMAP; p != NULL; p = p->next)
		if (p->status == STATUS_MAPPED && ((void *)p + METADATA_SIZE) == ptr) {
			if (p->prev)
				p->prev->next = p->next;
			if (p->next)
				p->next->prev = p->prev;
			if (p->prev == NULL)
				BM_header_MMAP = p->next;
			int result = 0;
			// result -> result of munmap
			result = munmap(p, METADATA_SIZE + p->size);
			DIE(result == -1, "MUNMAP: error");
			break;
		}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	struct block_meta *current_BM_ptr = NULL;
	size_t BM_size = ALIGN(nmemb * size);

	if (BM_size == 0)
		return NULL;
	if (METADATA_SIZE + BM_size < (size_t)getpagesize()) {
		void *new_ptr = NULL;
		// new_ptr -> payload of The New Block
		new_ptr = SBRK_Allocation(current_BM_ptr, BM_size);
		if (!new_ptr)
			return NULL;
		struct block_meta *new_BM_ptr = NULL;
		// new_BM_ptr -> The New Block
		new_BM_ptr = new_ptr - METADATA_SIZE;
		// Initialize The New Block
		for (size_t i = 0; i < new_BM_ptr->size; i++)
			*((char *)new_BM_ptr + METADATA_SIZE + i) = 0;
		return (void *)new_BM_ptr + METADATA_SIZE;
	}
	void *new_ptr = NULL;
	// new_ptr -> payload of The New Block
	new_ptr = MMAP_Allocation(current_BM_ptr, BM_size);
	if (!new_ptr)
		return NULL;
	struct block_meta *new_BM_ptr = NULL;
	// new_BM_ptr -> The New Block
	new_BM_ptr = new_ptr - METADATA_SIZE;
	// Initialize The New Block
	for (size_t i = 0; i < new_BM_ptr->size; i++)
		*((char *)new_BM_ptr + METADATA_SIZE + i) = 0;
	return (void *)new_BM_ptr + METADATA_SIZE;
}

void *SBRK_reallocation(struct block_meta *current_BM_ptr, size_t BM_size)
{
	if (current_BM_ptr->status == STATUS_FREE)
		return NULL;
	if (current_BM_ptr->size >= BM_size) {
		if (current_BM_ptr->size >= BM_size + METADATA_SIZE + ALIGNMENT)
			SBRK_Split_Block(current_BM_ptr, BM_size);
		return (void *)current_BM_ptr + METADATA_SIZE;
	}
	if (current_BM_ptr->next && current_BM_ptr->next->status == STATUS_FREE) {
		if ((current_BM_ptr->size + METADATA_SIZE + current_BM_ptr->next->size) >= BM_size) {
			current_BM_ptr->size = current_BM_ptr->size + METADATA_SIZE + current_BM_ptr->next->size;
			current_BM_ptr->next = current_BM_ptr->next->next;
			if (current_BM_ptr->next)
				current_BM_ptr->next->prev = current_BM_ptr;
			if (current_BM_ptr->size > BM_size + METADATA_SIZE + ALIGNMENT)
				SBRK_Split_Block(current_BM_ptr, BM_size);
			return (void *)current_BM_ptr + METADATA_SIZE;
		}
		void *new_ptr = NULL;
		// new_ptr -> payload of The New Block
		new_ptr = os_malloc(BM_size);
		DIE(new_ptr == NULL, "REALLOC with SBRK: malloc failed");
		struct block_meta *new_BM_ptr = NULL;
		// new_BM_ptr -> The New Block
		new_BM_ptr = new_ptr - METADATA_SIZE;
		// Copy The Current Block in The New Block
		for (size_t i = 0; i < current_BM_ptr->size; i++)
			*((char *)new_BM_ptr + METADATA_SIZE + i) = *((char *)current_BM_ptr + METADATA_SIZE + i);
		os_free((void *)current_BM_ptr + METADATA_SIZE);
		return (void *)new_BM_ptr + METADATA_SIZE;
	}
	if (!current_BM_ptr->next) {
		SBRK_Extend_Block(current_BM_ptr, BM_size);
		return (void *)current_BM_ptr + METADATA_SIZE;
	}
	void *new_ptr = NULL;
	// new_ptr -> payload of The New Block
	new_ptr = os_malloc(BM_size);
	DIE(new_ptr == NULL, "REALLOC with SBRK: malloc failed");
	struct block_meta *new_BM_ptr = NULL;
	// new_BM_ptr -> The New Block
	new_BM_ptr = new_ptr - METADATA_SIZE;
	// Copy The Current Block in The New Block
	for (size_t i = 0; i < current_BM_ptr->size; i++)
		*((char *)new_BM_ptr + METADATA_SIZE + i) = *((char *)current_BM_ptr + METADATA_SIZE + i);
	os_free((void *)current_BM_ptr + METADATA_SIZE);
	return (void *)new_BM_ptr + METADATA_SIZE;
}

void *MMAP_reallocation(struct block_meta *current_BM_ptr, size_t BM_size)
{
	if (current_BM_ptr->status == STATUS_FREE)
		return NULL;
	void *new_ptr = NULL;
	// new_ptr -> payload of The New Block
	new_ptr = os_malloc(BM_size);
	DIE(new_ptr == NULL, "REALLOC with MMAP: malloc failed");
	struct block_meta *new_BM_ptr = NULL;
	// new_BM_ptr -> The New Block
	new_BM_ptr = new_ptr - METADATA_SIZE;
	// Copy The Current Block in The New Block
	if (current_BM_ptr->size <= new_BM_ptr->size) {
		for (size_t i = 0; i < current_BM_ptr->size; i++)
			*((char *)new_BM_ptr + METADATA_SIZE + i) = *((char *)current_BM_ptr + METADATA_SIZE + i);
	}
	if (current_BM_ptr->size > new_BM_ptr->size) {
		for (size_t i = 0; i < new_BM_ptr->size; i++)
			*((char *)new_BM_ptr + METADATA_SIZE + i) = *((char *)current_BM_ptr + METADATA_SIZE + i);
	}
	os_free((void *)current_BM_ptr + METADATA_SIZE);
	return (void *)new_BM_ptr + METADATA_SIZE;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	struct block_meta *current_BM_ptr = NULL;
	size_t BM_size = ALIGN(size);

	if (!ptr)
		return os_malloc(size);
	if (BM_size == 0) {
		os_free(ptr);
		return NULL;
	}
	SBRK_Coalesce_Blocks();
	current_BM_ptr = BM_header_SBRK;
	while (current_BM_ptr) {
		if (((void *)current_BM_ptr + METADATA_SIZE) == ptr)
			return SBRK_reallocation(current_BM_ptr, BM_size);
		current_BM_ptr = current_BM_ptr->next;
	}
	MMAP_Coalesce_Blocks();
	current_BM_ptr = BM_header_MMAP;
	while (current_BM_ptr) {
		if (((void *)current_BM_ptr + METADATA_SIZE) == ptr)
			return MMAP_reallocation(current_BM_ptr, BM_size);
		current_BM_ptr = current_BM_ptr->next;
	}
	return NULL;
}
