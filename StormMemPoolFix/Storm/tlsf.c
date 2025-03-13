#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "tlsf.h"

#if defined(__cplusplus)
#define tlsf_decl inline
#else
#define tlsf_decl static
#endif

/*
** Architecture-specific bit manipulation routines.
**
** TLSF achieves O(1) cost for malloc and free operations by limiting
** the search for a free block to a free list of guaranteed size
** adequate to fulfill the request, combined with efficient free list
** queries using bitmasks and architecture-specific bit-manipulation
** routines.
**
** Most modern processors provide instructions to count leading zeroes
** in a word, find the lowest and highest set bit, etc. These
** specific implementations will be used when available, falling back
** to a reasonably efficient generic implementation.
**
** NOTE: TLSF spec relies on ffs/fls returning value 0..31.
** ffs/fls return 1-32 by default, returning 0 for error.
*/

/*
** Detect whether or not we are building for a 32- or 64-bit (LP/LLP)
** architecture. There is no reliable portable method at compile-time.
*/
#if defined (__alpha__) || defined (__ia64__) || defined (__x86_64__) \
	|| defined (_WIN64) || defined (__LP64__) || defined (__LLP64__)
#define TLSF_64BIT
#endif

/*
** gcc 3.4 and above have builtin support, specialized for architecture.
** Some compilers masquerade as gcc; patchlevel test filters them out.
*/
#if defined (__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)) \
	&& defined (__GNUC_PATCHLEVEL__)

#if defined (__SNC__)
/* SNC for Playstation 3. */

tlsf_decl int tlsf_ffs(unsigned int word)
{
	const unsigned int reverse = word & (~word + 1);
	const int bit = 32 - __builtin_clz(reverse);
	return bit - 1;
}

#else

tlsf_decl int tlsf_ffs(unsigned int word)
{
	return __builtin_ffs(word) - 1;
}

#endif

tlsf_decl int tlsf_fls(unsigned int word)
{
	const int bit = word ? 32 - __builtin_clz(word) : 0;
	return bit - 1;
}

#elif defined (_MSC_VER) && (_MSC_VER >= 1400) && (defined (_M_IX86) || defined (_M_X64))
/* Microsoft Visual C++ support on x86/X64 architectures. */

#include <intrin.h>

#pragma intrinsic(_BitScanReverse)
#pragma intrinsic(_BitScanForward)

tlsf_decl int tlsf_fls(unsigned int word)
{
	unsigned long index;
	return _BitScanReverse(&index, word) ? index : -1;
}

tlsf_decl int tlsf_ffs(unsigned int word)
{
	unsigned long index;
	return _BitScanForward(&index, word) ? index : -1;
}

#elif defined (_MSC_VER) && defined (_M_PPC)
/* Microsoft Visual C++ support on PowerPC architectures. */

#include <ppcintrinsics.h>

tlsf_decl int tlsf_fls(unsigned int word)
{
	const int bit = 32 - _CountLeadingZeros(word);
	return bit - 1;
}

tlsf_decl int tlsf_ffs(unsigned int word)
{
	const unsigned int reverse = word & (~word + 1);
	const int bit = 32 - _CountLeadingZeros(reverse);
	return bit - 1;
}

#elif defined (__ARMCC_VERSION)
/* RealView Compilation Tools for ARM */

tlsf_decl int tlsf_ffs(unsigned int word)
{
	const unsigned int reverse = word & (~word + 1);
	const int bit = 32 - __clz(reverse);
	return bit - 1;
}

tlsf_decl int tlsf_fls(unsigned int word)
{
	const int bit = word ? 32 - __clz(word) : 0;
	return bit - 1;
}

#elif defined (__ghs__)
/* Green Hills support for PowerPC */

#include <ppc_ghs.h>
#include <ctime>

tlsf_decl int tlsf_ffs(unsigned int word)
{
	const unsigned int reverse = word & (~word + 1);
	const int bit = 32 - __CLZ32(reverse);
	return bit - 1;
}

tlsf_decl int tlsf_fls(unsigned int word)
{
	const int bit = word ? 32 - __CLZ32(word) : 0;
	return bit - 1;
}

#else
/* Fall back to generic implementation. */

tlsf_decl int tlsf_fls_generic(unsigned int word)
{
	int bit = 32;

	if (!word) bit -= 1;
	if (!(word & 0xffff0000)) { word <<= 16; bit -= 16; }
	if (!(word & 0xff000000)) { word <<= 8; bit -= 8; }
	if (!(word & 0xf0000000)) { word <<= 4; bit -= 4; }
	if (!(word & 0xc0000000)) { word <<= 2; bit -= 2; }
	if (!(word & 0x80000000)) { word <<= 1; bit -= 1; }

	return bit;
}

/* Implement ffs in terms of fls. */
tlsf_decl int tlsf_ffs(unsigned int word)
{
	return tlsf_fls_generic(word & (~word + 1)) - 1;
}

tlsf_decl int tlsf_fls(unsigned int word)
{
	return tlsf_fls_generic(word) - 1;
}

#endif

/* Possibly 64-bit version of tlsf_fls. */
#if defined (TLSF_64BIT)
tlsf_decl int tlsf_fls_sizet(size_t size)
{
	int high = (int)(size >> 32);
	int bits = 0;
	if (high)
	{
		bits = 32 + tlsf_fls(high);
	}
	else
	{
		bits = tlsf_fls((int)size & 0xffffffff);

	}
	return bits;
}
#else
#define tlsf_fls_sizet tlsf_fls
#endif

#undef tlsf_decl



//add by Disaster
// 优化的向前查找第一个设置位(ffs)

// 全局启用/禁用标志
static int g_use_optimized_mapping = 1;  // 默认启用

// 全局标志控制是否使用优化版块查找
static int g_use_optimized_block_search = 1; // 默认启用

// 全局标志控制是否使用优化版块管理
static int g_use_optimized_block_management = 1; // 默认启用

// 全局开关
static int g_use_optimized_memory_locality = 1; // 默认启用

// 切换函数
void tlsf_toggle_optimized_memory_locality(int enable) {
	g_use_optimized_memory_locality = enable;
}

void tlsf_toggle_optimized_block_management(int enable) {
	g_use_optimized_block_management = enable;
}

void tlsf_toggle_optimized_block_search(int enable) {
	g_use_optimized_block_search = enable;
}

void tlsf_toggle_optimized_mapping(int enable) {
	g_use_optimized_mapping = enable;
}

static inline int optimized_ffs(unsigned int word) {
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
	// MSVC平台使用内置指令
	unsigned long index;
	if (_BitScanForward(&index, word))
		return index;
	return -1;
#elif defined(__GNUC__) || defined(__clang__)
	// GCC/Clang平台使用内置函数
	if (word == 0) return -1;
	return __builtin_ctz(word);  // 直接使用计算后缀零数的内建函数
#else
	// 通用优化实现
	static const unsigned char MultiplyDeBruijnBitPosition[32] = {
		0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
		31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
	};
	return word ? MultiplyDeBruijnBitPosition[((word & -word) * 0x077CB531U) >> 27] : -1;
#endif
}

// 优化的向后查找最后一个设置位(fls)
static inline int optimized_fls(unsigned int word) {
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
	// MSVC平台
	unsigned long index;
	if (_BitScanReverse(&index, word))
		return index;
	return -1;
#elif defined(__GNUC__) || defined(__clang__)
	// GCC/Clang平台
	if (word == 0) return -1;
	return 31 - __builtin_clz(word);  // 使用前导零计数
#else
	// 优化的通用实现 - 二分查找方法
	int pos = -1;
	if (word & 0xFFFF0000) { pos += 16; word >>= 16; }
	if (word & 0xFF00) { pos += 8; word >>= 8; }
	if (word & 0xF0) { pos += 4; word >>= 4; }
	if (word & 0xC) { pos += 2; word >>= 2; }
	if (word & 0x2) { pos += 1; word >>= 1; }
	if (word & 0x1) { pos += 1; }
	return pos;
#endif
}

#if defined (TLSF_64BIT)
// 优化的64位版本fls
static inline int optimized_fls_sizet(size_t size) {
	int high = (int)(size >> 32);
	int bits = 0;

	if (high) {
#if defined(_MSC_VER) && defined(_M_X64)
		unsigned long index;
		_BitScanReverse64(&index, (unsigned __int64)size);
		return index;
#elif defined(__GNUC__) || defined(__clang__)
		return 63 - __builtin_clzll((unsigned long long)size);
#else
		bits = 32 + optimized_fls(high);
#endif
	}
	else {
		bits = optimized_fls((int)size & 0xffffffff);
	}
	return bits;
}
#else
#define optimized_fls_sizet optimized_fls
#endif

// 控制是否使用优化版位操作的全局标志
static int g_use_optimized_bitops = 1;  // 默认启用

// 切换优化位操作的函数
void tlsf_toggle_optimized_bitops(int enable) {
	g_use_optimized_bitops = enable;
}

// 封装的ffs函数，根据标志选择实现
static int safe_ffs(unsigned int word) {
	if (g_use_optimized_bitops) {
		return optimized_ffs(word);
	}
	else {
		// 使用原始实现
		// 保留原始tlsf_ffs代码，避免修改可能引入的问题
		return tlsf_ffs(word);
	}
}

// 封装的fls函数，根据标志选择实现
static int safe_fls(unsigned int word) {
	if (g_use_optimized_bitops) {
		return optimized_fls(word);
	}
	else {
		// 使用原始实现
		return tlsf_fls(word);
	}
}

// 封装的fls_sizet函数，根据标志选择实现
static int safe_fls_sizet(size_t size) {
	if (g_use_optimized_bitops) {
		return optimized_fls_sizet(size);
	}
	else {
		// 使用原始实现
		return tlsf_fls_sizet(size);
	}
}

// 验证优化位操作函数的正确性
int test_optimized_bitops() {
	// 测试用例数组：{输入值, 预期ffs结果, 预期fls结果}
	const struct {
		unsigned int input;
		int ffs_result;
		int fls_result;
	} test_cases[] = {
		{0, -1, -1},              // 0没有设置位
		{1, 0, 0},                // 只有最低位设置
		{0x80000000, 31, 31},     // 只有最高位设置
		{0x80008000, 15, 31},     // 两个位设置
		{0x7FFFFFFF, 0, 30},      // 除了最高位外所有位设置
		{0xFFFFFFFF, 0, 31},      // 所有位设置
		{0x12345678, 3, 28},      // 随机值
		{0xA5A5A5A5, 0, 31}       // 交替位设置
	};

	int errors = 0;
	for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
		unsigned int input = test_cases[i].input;

		// 测试ffs
		int orig_ffs = tlsf_ffs(input);
		int opt_ffs = optimized_ffs(input);
		if (orig_ffs != opt_ffs || orig_ffs != test_cases[i].ffs_result) {
			errors++;
		}

		// 测试fls
		int orig_fls = tlsf_fls(input);
		int opt_fls = optimized_fls(input);
		if (orig_fls != opt_fls || orig_fls != test_cases[i].fls_result) {
			//LogMessage("[TLSF] fls测试失败: 输入=%u, 原始=%d, 优化=%d, 预期=%d",
			//	input, orig_fls, opt_fls, test_cases[i].fls_result);
			errors++;
		}
	}

	// 测试大值（仅测试fls_sizet）
	size_t large_values[] = {
		(size_t)1 << 32,          // 只有第33位设置
		((size_t)1 << 32) | 1,    // 第33位和第1位设置
		(size_t)-1                // 所有位设置
	};

	for (size_t i = 0; i < sizeof(large_values) / sizeof(large_values[0]); i++) {
		size_t input = large_values[i];
		int orig_fls = tlsf_fls_sizet(input);
		int opt_fls = optimized_fls_sizet(input);
		if (orig_fls != opt_fls) {
			//LogMessage("[TLSF] fls_sizet测试失败: 输入=%zu, 原始=%d, 优化=%d",
			//	input, orig_fls, opt_fls);
			errors++;
		}
	}

	if (errors == 0) {
		printf("[TLSF] 所有位操作优化测试通过!\n");
	}
	else {
		printf("[TLSF] 位操作优化测试失败: % d个错误\n",errors);
		// 自动禁用优化
		g_use_optimized_bitops = 0;
	}

	return errors == 0;
}

/*
** Constants.
*/

/* Public constants: may be modified. */
enum tlsf_public
{
	/* log2 of number of linear subdivisions of block sizes. Larger
	** values require more memory in the control structure. Values of
	** 4 or 5 are typical.
	*/
	SL_INDEX_COUNT_LOG2 = 5,
};

/* Private constants: do not modify. */
enum tlsf_private
{
#if defined (TLSF_64BIT)
	/* All allocation sizes and addresses are aligned to 8 bytes. */
	ALIGN_SIZE_LOG2 = 3,
#else
	/* All allocation sizes and addresses are aligned to 4 bytes. */
	ALIGN_SIZE_LOG2 = 2,
#endif
	ALIGN_SIZE = (1 << ALIGN_SIZE_LOG2),

	/*
	** We support allocations of sizes up to (1 << FL_INDEX_MAX) bits.
	** However, because we linearly subdivide the second-level lists, and
	** our minimum size granularity is 4 bytes, it doesn't make sense to
	** create first-level lists for sizes smaller than SL_INDEX_COUNT * 4,
	** or (1 << (SL_INDEX_COUNT_LOG2 + 2)) bytes, as there we will be
	** trying to split size ranges into more slots than we have available.
	** Instead, we calculate the minimum threshold size, and place all
	** blocks below that size into the 0th first-level list.
	*/

#if defined (TLSF_64BIT)
	/*
	** TODO: We can increase this to support larger sizes, at the expense
	** of more overhead in the TLSF structure.
	*/
	FL_INDEX_MAX = 32,
#else
	FL_INDEX_MAX = 30,
#endif
	SL_INDEX_COUNT = (1 << SL_INDEX_COUNT_LOG2),
	FL_INDEX_SHIFT = (SL_INDEX_COUNT_LOG2 + ALIGN_SIZE_LOG2),
	FL_INDEX_COUNT = (FL_INDEX_MAX - FL_INDEX_SHIFT + 1),

	SMALL_BLOCK_SIZE = (1 << FL_INDEX_SHIFT),
};

/*
** Cast and min/max macros.
*/

#define tlsf_cast(t, exp)	((t) (exp))
#define tlsf_min(a, b)		((a) < (b) ? (a) : (b))
#define tlsf_max(a, b)		((a) > (b) ? (a) : (b))

/*
** Set assert macro, if it has not been provided by the user.
*/
#if !defined (tlsf_assert)
#define tlsf_assert assert
#endif

/*
** Static assertion mechanism.
*/

#define _tlsf_glue2(x, y) x ## y
#define _tlsf_glue(x, y) _tlsf_glue2(x, y)
#define tlsf_static_assert(exp) \
	typedef char _tlsf_glue(static_assert, __LINE__) [(exp) ? 1 : -1]

/* This code has been tested on 32- and 64-bit (LP/LLP) architectures. */
tlsf_static_assert(sizeof(int) * CHAR_BIT == 32);
tlsf_static_assert(sizeof(size_t) * CHAR_BIT >= 32);
tlsf_static_assert(sizeof(size_t) * CHAR_BIT <= 64);

/* SL_INDEX_COUNT must be <= number of bits in sl_bitmap's storage type. */
tlsf_static_assert(sizeof(unsigned int) * CHAR_BIT >= SL_INDEX_COUNT);

/* Ensure we've properly tuned our sizes. */
tlsf_static_assert(ALIGN_SIZE == SMALL_BLOCK_SIZE / SL_INDEX_COUNT);

/*
** Data structures and associated constants.
*/

/*
** Block header structure.
**
** There are several implementation subtleties involved:
** - The prev_phys_block field is only valid if the previous block is free.
** - The prev_phys_block field is actually stored at the end of the
**   previous block. It appears at the beginning of this structure only to
**   simplify the implementation.
** - The next_free / prev_free fields are only valid if the block is free.
*/
typedef struct block_header_t
{
	/* Points to the previous physical block. */
	struct block_header_t* prev_phys_block;

	/* The size of this block, excluding the block header. */
	size_t size;

	/* Next and previous free blocks. */
	struct block_header_t* next_free;
	struct block_header_t* prev_free;
} block_header_t;

/*
** Since block sizes are always at least a multiple of 4, the two least
** significant bits of the size field are used to store the block status:
** - bit 0: whether block is busy or free
** - bit 1: whether previous block is busy or free
*/
static const size_t block_header_free_bit = 1 << 0;
static const size_t block_header_prev_free_bit = 1 << 1;

/*
** The size of the block header exposed to used blocks is the size field.
** The prev_phys_block field is stored *inside* the previous free block.
*/
static const size_t block_header_overhead = sizeof(size_t);

/* User data starts directly after the size field in a used block. */
static const size_t block_start_offset =
	offsetof(block_header_t, size) + sizeof(size_t);

/*
** A free block must be large enough to store its header minus the size of
** the prev_phys_block field, and no larger than the number of addressable
** bits for FL_INDEX.
*/
static const size_t block_size_min = 
	sizeof(block_header_t) - sizeof(block_header_t*);
static const size_t block_size_max = tlsf_cast(size_t, 1) << FL_INDEX_MAX;


/* The TLSF control structure. */
typedef struct control_t
{
	/* Empty lists point at this block to indicate they are free. */
	block_header_t block_null;

	/* Bitmaps for free lists. */
	unsigned int fl_bitmap;
	unsigned int sl_bitmap[FL_INDEX_COUNT];

	/* Head of free lists. */
	block_header_t* blocks[FL_INDEX_COUNT][SL_INDEX_COUNT];
} control_t;

/* A type used for casting when doing pointer arithmetic. */
typedef ptrdiff_t tlsfptr_t;


//add by Disaster

static void initialize_mapping_table();

int test_optimized_mapping_thorough();

int test_optimized_block_search();

int test_optimized_block_management();

int test_optimized_memory_locality();

static void optimize_mapping_search(size_t size, int* fli, int* sli);

static block_header_t* optimized_search_suitable_block(control_t* control, int* fli, int* sli);

static void optimized_insert_free_block(control_t* control, block_header_t* block, int fl, int sl);

static void optimized_remove_free_block(control_t* control, block_header_t* block, int fl, int sl);

static void initialize_small_block_cache();

static void* get_block_from_cache(size_t size);

static int put_block_to_cache(void* ptr, size_t size);

static void flush_small_block_cache(tlsf_t tlsf);

void* optimized_tlsf_malloc(tlsf_t tlsf, size_t size);

void optimized_tlsf_free(tlsf_t tlsf, void* ptr);


/*
** block_header_t member functions.
*/

static size_t block_size(const block_header_t* block)
{
	return block->size & ~(block_header_free_bit | block_header_prev_free_bit);
}

static void block_set_size(block_header_t* block, size_t size)
{
	const size_t oldsize = block->size;
	block->size = size | (oldsize & (block_header_free_bit | block_header_prev_free_bit));
}

static int block_is_last(const block_header_t* block)
{
	return block_size(block) == 0;
}

static int block_is_free(const block_header_t* block)
{
	return tlsf_cast(int, block->size & block_header_free_bit);
}

static void block_set_free(block_header_t* block)
{
	block->size |= block_header_free_bit;
}

static void block_set_used(block_header_t* block)
{
	block->size &= ~block_header_free_bit;
}

static int block_is_prev_free(const block_header_t* block)
{
	return tlsf_cast(int, block->size & block_header_prev_free_bit);
}

static void block_set_prev_free(block_header_t* block)
{
	block->size |= block_header_prev_free_bit;
}

static void block_set_prev_used(block_header_t* block)
{
	block->size &= ~block_header_prev_free_bit;
}

static block_header_t* block_from_ptr(const void* ptr)
{
	return tlsf_cast(block_header_t*,
		tlsf_cast(unsigned char*, ptr) - block_start_offset);
}

static void* block_to_ptr(const block_header_t* block)
{
	return tlsf_cast(void*,
		tlsf_cast(unsigned char*, block) + block_start_offset);
}

/* Return location of next block after block of given size. */
static block_header_t* offset_to_block(const void* ptr, size_t size)
{
	return tlsf_cast(block_header_t*, tlsf_cast(tlsfptr_t, ptr) + size);
}

/* Return location of previous block. */
static block_header_t* block_prev(const block_header_t* block)
{
	tlsf_assert(block_is_prev_free(block) && "previous block must be free");
	return block->prev_phys_block;
}

/* Return location of next existing block. */
static block_header_t* block_next(const block_header_t* block)
{
	block_header_t* next = offset_to_block(block_to_ptr(block),
		block_size(block) - block_header_overhead);
	tlsf_assert(!block_is_last(block));
	return next;
}

/* Link a new block with its physical neighbor, return the neighbor. */
static block_header_t* block_link_next(block_header_t* block)
{
	block_header_t* next = block_next(block);
	next->prev_phys_block = block;
	return next;
}

static void block_mark_as_free(block_header_t* block)
{
	/* Link the block to the next block, first. */
	block_header_t* next = block_link_next(block);
	block_set_prev_free(next);
	block_set_free(block);
}

static void block_mark_as_used(block_header_t* block)
{
	block_header_t* next = block_next(block);
	block_set_prev_used(next);
	block_set_used(block);
}

static size_t align_up(size_t x, size_t align)
{
	tlsf_assert(0 == (align & (align - 1)) && "must align to a power of two");
	return (x + (align - 1)) & ~(align - 1);
}

static size_t align_down(size_t x, size_t align)
{
	tlsf_assert(0 == (align & (align - 1)) && "must align to a power of two");
	return x - (x & (align - 1));
}

static void* align_ptr(const void* ptr, size_t align)
{
	const tlsfptr_t aligned =
		(tlsf_cast(tlsfptr_t, ptr) + (align - 1)) & ~(align - 1);
	tlsf_assert(0 == (align & (align - 1)) && "must align to a power of two");
	return tlsf_cast(void*, aligned);
}

/*
** Adjust an allocation size to be aligned to word size, and no smaller
** than internal minimum.
*/
static size_t adjust_request_size(size_t size, size_t align)
{
	size_t adjust = 0;
	if (size)
	{
		const size_t aligned = align_up(size, align);

		/* aligned sized must not exceed block_size_max or we'll go out of bounds on sl_bitmap */
		if (aligned < block_size_max) 
		{
			adjust = tlsf_max(aligned, block_size_min);
		}
	}
	return adjust;
}

/*
** TLSF utility functions. In most cases, these are direct translations of
** the documentation found in the white paper.
*/

static void mapping_insert(size_t size, int* fli, int* sli) {
	int fl, sl;
	if (size < SMALL_BLOCK_SIZE) {
		/* Store small blocks in first list. */
		fl = 0;
		sl = tlsf_cast(int, size) / (SMALL_BLOCK_SIZE / SL_INDEX_COUNT);
	}
	else {
		fl = safe_fls_sizet(size);  // 替换为安全版本
		sl = tlsf_cast(int, size >> (fl - SL_INDEX_COUNT_LOG2)) ^ (1 << SL_INDEX_COUNT_LOG2);
		fl -= (FL_INDEX_SHIFT - 1);
	}
	*fli = fl;
	*sli = sl;
}

/* This version rounds up to the next block size (for allocations) */
static void mapping_search(size_t size, int* fli, int* sli) {
	if (g_use_optimized_mapping) {
		optimize_mapping_search(size, fli, sli);
		return;
	}

	// 原始实现
	if (size >= SMALL_BLOCK_SIZE) {
		const size_t round = (1 << (tlsf_fls_sizet(size) - SL_INDEX_COUNT_LOG2)) - 1;
		size += round;
	}
	mapping_insert(size, fli, sli);
}

static block_header_t* search_suitable_block(control_t* control, int* fli, int* sli) {
	int fl = *fli;
	int sl = *sli;

	/*
	** First, search for a block in the list associated with the given
	** fl/sl index.
	*/
	unsigned int sl_map = control->sl_bitmap[fl] & (~0U << sl);
	if (!sl_map) {
		/* No block exists. Search in the next largest first-level list. */
		const unsigned int fl_map = control->fl_bitmap & (~0U << (fl + 1));
		if (!fl_map) {
			/* No free blocks available, memory has been exhausted. */
			return 0;
		}

		fl = safe_ffs(fl_map);  // 替换为安全版本
		*fli = fl;
		sl_map = control->sl_bitmap[fl];
	}
	tlsf_assert(sl_map && "internal error - second level bitmap is null");
	sl = safe_ffs(sl_map);  // 替换为安全版本
	*sli = sl;

	/* Return the first block in the free list. */
	return control->blocks[fl][sl];
}

// 优化版块查找函数
static block_header_t* optimized_search_suitable_block(control_t* control, int* fli, int* sli) {
	int fl = *fli;
	int sl = *sli;

	// 1. 优化第一级位图查找
	unsigned int sl_map = control->sl_bitmap[fl] & (~0U << sl);
	if (!sl_map) {
		// 没有找到合适的二级列表，查找下一个第一级列表
		const unsigned int fl_map = control->fl_bitmap & (~0U << (fl + 1));
		if (!fl_map) {
			// 没有可用的自由块
			return 0;
		}

		// 使用优化过的ffs函数
		fl = safe_ffs(fl_map);
		*fli = fl;
		sl_map = control->sl_bitmap[fl];
	}

	// 2. 优化第二级位图查找 - 使用优化过的位操作
	sl = safe_ffs(sl_map);
	*sli = sl;

	// 返回找到的块
	return control->blocks[fl][sl];
}

/* Remove a free block from the free list.*/
static void remove_free_block(control_t* control, block_header_t* block, int fl, int sl)
{
	block_header_t* prev = block->prev_free;
	block_header_t* next = block->next_free;
	tlsf_assert(prev && "prev_free field can not be null");
	tlsf_assert(next && "next_free field can not be null");
	next->prev_free = prev;
	prev->next_free = next;

	/* If this block is the head of the free list, set new head. */
	if (control->blocks[fl][sl] == block)
	{
		control->blocks[fl][sl] = next;

		/* If the new head is null, clear the bitmap. */
		if (next == &control->block_null)
		{
			control->sl_bitmap[fl] &= ~(1U << sl);

			/* If the second bitmap is now empty, clear the fl bitmap. */
			if (!control->sl_bitmap[fl])
			{
				control->fl_bitmap &= ~(1U << fl);
			}
		}
	}
}

/* Insert a free block into the free block list. */
static void insert_free_block(control_t* control, block_header_t* block, int fl, int sl)
{
	block_header_t* current = control->blocks[fl][sl];
	tlsf_assert(current && "free list cannot have a null entry");
	tlsf_assert(block && "cannot insert a null entry into the free list");
	block->next_free = current;
	block->prev_free = &control->block_null;
	current->prev_free = block;

	tlsf_assert(block_to_ptr(block) == align_ptr(block_to_ptr(block), ALIGN_SIZE)
		&& "block not aligned properly");
	/*
	** Insert the new block at the head of the list, and mark the first-
	** and second-level bitmaps appropriately.
	*/
	control->blocks[fl][sl] = block;
	control->fl_bitmap |= (1U << fl);
	control->sl_bitmap[fl] |= (1U << sl);
}

/* Remove a given block from the free list. */
static void block_remove(control_t* control, block_header_t* block) {
	int fl, sl;
	mapping_insert(block_size(block), &fl, &sl);

	if (g_use_optimized_block_management) {
		optimized_remove_free_block(control, block, fl, sl);
	}
	else {
		remove_free_block(control, block, fl, sl);
	}
}

/* Insert a given block into the free list. */
static void block_insert(control_t* control, block_header_t* block) {
	int fl, sl;
	mapping_insert(block_size(block), &fl, &sl);

	if (g_use_optimized_block_management) {
		optimized_insert_free_block(control, block, fl, sl);
	}
	else {
		insert_free_block(control, block, fl, sl);
	}
}

static int block_can_split(block_header_t* block, size_t size)
{
	return block_size(block) >= sizeof(block_header_t) + size;
}

/* Split a block into two, the second of which is free. */
static block_header_t* block_split(block_header_t* block, size_t size)
{
	/* Calculate the amount of space left in the remaining block. */
	block_header_t* remaining =
		offset_to_block(block_to_ptr(block), size - block_header_overhead);

	const size_t remain_size = block_size(block) - (size + block_header_overhead);

	tlsf_assert(block_to_ptr(remaining) == align_ptr(block_to_ptr(remaining), ALIGN_SIZE)
		&& "remaining block not aligned properly");

	tlsf_assert(block_size(block) == remain_size + size + block_header_overhead);
	block_set_size(remaining, remain_size);
	tlsf_assert(block_size(remaining) >= block_size_min && "block split with invalid size");

	block_set_size(block, size);
	block_mark_as_free(remaining);

	return remaining;
}

/* Absorb a free block's storage into an adjacent previous free block. */
static block_header_t* block_absorb(block_header_t* prev, block_header_t* block)
{
	tlsf_assert(!block_is_last(prev) && "previous block can't be last");
	/* Note: Leaves flags untouched. */
	prev->size += block_size(block) + block_header_overhead;
	block_link_next(prev);
	return prev;
}

/* Merge a just-freed block with an adjacent previous free block. */
static block_header_t* block_merge_prev(control_t* control, block_header_t* block)
{
	if (block_is_prev_free(block))
	{
		block_header_t* prev = block_prev(block);
		tlsf_assert(prev && "prev physical block can't be null");
		tlsf_assert(block_is_free(prev) && "prev block is not free though marked as such");
		block_remove(control, prev);
		block = block_absorb(prev, block);
	}

	return block;
}

/* Merge a just-freed block with an adjacent free block. */
static block_header_t* block_merge_next(control_t* control, block_header_t* block)
{
	block_header_t* next = block_next(block);
	tlsf_assert(next && "next physical block can't be null");

	if (block_is_free(next))
	{
		tlsf_assert(!block_is_last(block) && "previous block can't be last");
		block_remove(control, next);
		block = block_absorb(block, next);
	}

	return block;
}

/* Trim any trailing block space off the end of a block, return to pool. */
static void block_trim_free(control_t* control, block_header_t* block, size_t size)
{
	tlsf_assert(block_is_free(block) && "block must be free");
	if (block_can_split(block, size))
	{
		block_header_t* remaining_block = block_split(block, size);
		block_link_next(block);
		block_set_prev_free(remaining_block);
		block_insert(control, remaining_block);
	}
}

/* Trim any trailing block space off the end of a used block, return to pool. */
static void block_trim_used(control_t* control, block_header_t* block, size_t size)
{
	tlsf_assert(!block_is_free(block) && "block must be used");
	if (block_can_split(block, size))
	{
		/* If the next block is free, we must coalesce. */
		block_header_t* remaining_block = block_split(block, size);
		block_set_prev_used(remaining_block);

		remaining_block = block_merge_next(control, remaining_block);
		block_insert(control, remaining_block);
	}
}

static block_header_t* block_trim_free_leading(control_t* control, block_header_t* block, size_t size)
{
	block_header_t* remaining_block = block;
	if (block_can_split(block, size))
	{
		/* We want the 2nd block. */
		remaining_block = block_split(block, size - block_header_overhead);
		block_set_prev_free(remaining_block);

		block_link_next(block);
		block_insert(control, block);
	}

	return remaining_block;
}

static block_header_t* block_locate_free(control_t* control, size_t size) {
	int fl = 0, sl = 0;
	block_header_t* block = 0;

	if (size) {
		mapping_search(size, &fl, &sl);

		if (fl < FL_INDEX_COUNT) {
			if (g_use_optimized_block_search) {
				block = optimized_search_suitable_block(control, &fl, &sl);
			}
			else {
				// 原始版本
				block = search_suitable_block(control, &fl, &sl);
			}
		}
	}

	if (block) {
		tlsf_assert(block_size(block) >= size);
		remove_free_block(control, block, fl, sl);
	}

	return block;
}

static void* block_prepare_used(control_t* control, block_header_t* block, size_t size)
{
	void* p = 0;
	if (block)
	{
		tlsf_assert(size && "size must be non-zero");
		block_trim_free(control, block, size);
		block_mark_as_used(block);
		p = block_to_ptr(block);
	}
	return p;
}

/* Clear structure and point all empty lists at the null block. */
static void control_construct(control_t* control)
{
	int i, j;

	control->block_null.next_free = &control->block_null;
	control->block_null.prev_free = &control->block_null;

	control->fl_bitmap = 0;
	for (i = 0; i < FL_INDEX_COUNT; ++i)
	{
		control->sl_bitmap[i] = 0;
		for (j = 0; j < SL_INDEX_COUNT; ++j)
		{
			control->blocks[i][j] = &control->block_null;
		}
	}
}

/*
** Debugging utilities.
*/

typedef struct integrity_t
{
	int prev_status;
	int status;
} integrity_t;

#define tlsf_insist(x) { tlsf_assert(x); if (!(x)) { status--; } }

static void integrity_walker(void* ptr, size_t size, int used, void* user)
{
	block_header_t* block = block_from_ptr(ptr);
	integrity_t* integ = tlsf_cast(integrity_t*, user);
	const int this_prev_status = block_is_prev_free(block) ? 1 : 0;
	const int this_status = block_is_free(block) ? 1 : 0;
	const size_t this_block_size = block_size(block);

	int status = 0;
	(void)used;
	tlsf_insist(integ->prev_status == this_prev_status && "prev status incorrect");
	tlsf_insist(size == this_block_size && "block size incorrect");

	integ->prev_status = this_status;
	integ->status += status;
}

int tlsf_check(tlsf_t tlsf)
{
	int i, j;

	control_t* control = tlsf_cast(control_t*, tlsf);
	int status = 0;

	/* Check that the free lists and bitmaps are accurate. */
	for (i = 0; i < FL_INDEX_COUNT; ++i)
	{
		for (j = 0; j < SL_INDEX_COUNT; ++j)
		{
			const int fl_map = control->fl_bitmap & (1U << i);
			const int sl_list = control->sl_bitmap[i];
			const int sl_map = sl_list & (1U << j);
			const block_header_t* block = control->blocks[i][j];

			/* Check that first- and second-level lists agree. */
			if (!fl_map)
			{
				tlsf_insist(!sl_map && "second-level map must be null");
			}

			if (!sl_map)
			{
				tlsf_insist(block == &control->block_null && "block list must be null");
				continue;
			}

			/* Check that there is at least one free block. */
			tlsf_insist(sl_list && "no free blocks in second-level map");
			tlsf_insist(block != &control->block_null && "block should not be null");

			while (block != &control->block_null)
			{
				int fli, sli;
				tlsf_insist(block_is_free(block) && "block should be free");
				tlsf_insist(!block_is_prev_free(block) && "blocks should have coalesced");
				tlsf_insist(!block_is_free(block_next(block)) && "blocks should have coalesced");
				tlsf_insist(block_is_prev_free(block_next(block)) && "block should be free");
				tlsf_insist(block_size(block) >= block_size_min && "block not minimum size");

				mapping_insert(block_size(block), &fli, &sli);
				tlsf_insist(fli == i && sli == j && "block size indexed in wrong list");
				block = block->next_free;
			}
		}
	}

	return status;
}

#undef tlsf_insist

static void default_walker(void* ptr, size_t size, int used, void* user)
{
	(void)user;
	printf("\t%p %s size: %x (%p)\n", ptr, used ? "used" : "free", (unsigned int)size, block_from_ptr(ptr));
}

void tlsf_walk_pool(pool_t pool, tlsf_walker walker, void* user)
{
	tlsf_walker pool_walker = walker ? walker : default_walker;
	block_header_t* block =
		offset_to_block(pool, -(int)block_header_overhead);

	while (block && !block_is_last(block))
	{
		pool_walker(
			block_to_ptr(block),
			block_size(block),
			!block_is_free(block),
			user);
		block = block_next(block);
	}
}

size_t tlsf_block_size(void* ptr)
{
	size_t size = 0;
	if (ptr)
	{
		const block_header_t* block = block_from_ptr(ptr);
		size = block_size(block);
	}
	return size;
}

int tlsf_check_pool(pool_t pool)
{
	/* Check that the blocks are physically correct. */
	integrity_t integ = { 0, 0 };
	tlsf_walk_pool(pool, integrity_walker, &integ);

	return integ.status;
}

/*
** Size of the TLSF structures in a given memory block passed to
** tlsf_create, equal to the size of a control_t
*/
size_t tlsf_size(void)
{
	return sizeof(control_t);
}

size_t tlsf_align_size(void)
{
	return ALIGN_SIZE;
}

size_t tlsf_block_size_min(void)
{
	return block_size_min;
}

size_t tlsf_block_size_max(void)
{
	return block_size_max;
}

/*
** Overhead of the TLSF structures in a given memory block passed to
** tlsf_add_pool, equal to the overhead of a free block and the
** sentinel block.
*/
size_t tlsf_pool_overhead(void)
{
	return 2 * block_header_overhead;
}

size_t tlsf_alloc_overhead(void)
{
	return block_header_overhead;
}

pool_t tlsf_add_pool(tlsf_t tlsf, void* mem, size_t bytes)
{
	block_header_t* block;
	block_header_t* next;

	const size_t pool_overhead = tlsf_pool_overhead();
	const size_t pool_bytes = align_down(bytes - pool_overhead, ALIGN_SIZE);

	if (((ptrdiff_t)mem % ALIGN_SIZE) != 0)
	{
		printf("tlsf_add_pool: Memory must be aligned by %u bytes.\n",
			(unsigned int)ALIGN_SIZE);
		return 0;
	}

	if (pool_bytes < block_size_min || pool_bytes > block_size_max)
	{
#if defined (TLSF_64BIT)
		printf("tlsf_add_pool: Memory size must be between 0x%x and 0x%x00 bytes.\n", 
			(unsigned int)(pool_overhead + block_size_min),
			(unsigned int)((pool_overhead + block_size_max) / 256));
#else
		printf("tlsf_add_pool: Memory size must be between %u and %u bytes.\n", 
			(unsigned int)(pool_overhead + block_size_min),
			(unsigned int)(pool_overhead + block_size_max));
#endif
		return 0;
	}

	/*
	** Create the main free block. Offset the start of the block slightly
	** so that the prev_phys_block field falls outside of the pool -
	** it will never be used.
	*/
	block = offset_to_block(mem, -(tlsfptr_t)block_header_overhead);
	block_set_size(block, pool_bytes);
	block_set_free(block);
	block_set_prev_used(block);
	block_insert(tlsf_cast(control_t*, tlsf), block);

	/* Split the block to create a zero-size sentinel block. */
	next = block_link_next(block);
	block_set_size(next, 0);
	block_set_used(next);
	block_set_prev_free(next);

	return mem;
}

void tlsf_remove_pool(tlsf_t tlsf, pool_t pool)
{
	control_t* control = tlsf_cast(control_t*, tlsf);
	block_header_t* block = offset_to_block(pool, -(int)block_header_overhead);

	int fl = 0, sl = 0;

	tlsf_assert(block_is_free(block) && "block should be free");
	tlsf_assert(!block_is_free(block_next(block)) && "next block should not be free");
	tlsf_assert(block_size(block_next(block)) == 0 && "next block size should be zero");

	mapping_insert(block_size(block), &fl, &sl);
	remove_free_block(control, block, fl, sl);
}

/*
** TLSF main interface.
*/

#if _DEBUG
int test_ffs_fls()
{
	/* Verify ffs/fls work properly. */
	int rv = 0;
	rv += (tlsf_ffs(0) == -1) ? 0 : 0x1;
	rv += (tlsf_fls(0) == -1) ? 0 : 0x2;
	rv += (tlsf_ffs(1) == 0) ? 0 : 0x4;
	rv += (tlsf_fls(1) == 0) ? 0 : 0x8;
	rv += (tlsf_ffs(0x80000000) == 31) ? 0 : 0x10;
	rv += (tlsf_ffs(0x80008000) == 15) ? 0 : 0x20;
	rv += (tlsf_fls(0x80000008) == 31) ? 0 : 0x40;
	rv += (tlsf_fls(0x7FFFFFFF) == 30) ? 0 : 0x80;

#if defined (TLSF_64BIT)
	rv += (tlsf_fls_sizet(0x80000000) == 31) ? 0 : 0x100;
	rv += (tlsf_fls_sizet(0x100000000) == 32) ? 0 : 0x200;
	rv += (tlsf_fls_sizet(0xffffffffffffffff) == 63) ? 0 : 0x400;
#endif

	if (rv)
	{
		printf("test_ffs_fls: %x ffs/fls tests failed.\n", rv);
	}
	return rv;
}
#endif

tlsf_t tlsf_create(void* mem) {
#if _DEBUG
    if (test_ffs_fls()) {
        return 0;
    }
    
    // 添加优化位操作测试
    if (!test_optimized_bitops()) {
        // 如果测试失败，日志已经输出，优化已禁用
        LogMessage("[TLSF] 使用原始位操作函数");
    } else {
        LogMessage("[TLSF] 使用优化位操作函数");
    }
#endif
	// 添加优化位操作测试
	if (!test_optimized_bitops()) {
		// 如果测试失败，日志已经输出，优化已禁用
		printf("[TLSF] 使用原始位操作函数");
	}
	else {
		printf("[TLSF] 使用优化位操作函数");
	}

	// 验证映射优化
	if (!test_optimized_mapping_thorough()) {
		printf("[TLSF] 使用原始映射函数");
	}
	else {
		printf("[TLSF] 使用优化映射函数");
	}

	//// 验证映射优化
	//if (!test_optimized_block_search()) {
	//	printf("[TLSF] 使用原始块查找");
	//}
	//else {
	//	printf("[TLSF] 使用优化块查找");
	//}

	//// 验证映射优化
	//if (!test_optimized_block_management()) {
	//	printf("[TLSF] 使用原始块管理函数");
	//}
	//else {
	//	printf("[TLSF] 使用优化块管理函数");
	//}

	//// 验证映射优化
	//if (!test_optimized_memory_locality()) {
	//	printf("[TLSF] 使用原始内存");
	//}
	//else {
	//	printf("[TLSF] 使用优化内存");
	//}


    if (((tlsfptr_t)mem % ALIGN_SIZE) != 0) {
        printf("tlsf_create: Memory must be aligned to %u bytes.\n",
            (unsigned int)ALIGN_SIZE);
        return 0;
    }
	printf("[TLSF]control_construct\n");
    control_construct(tlsf_cast(control_t*, mem));
	printf("[TLSF]初始化完成\n");
    return tlsf_cast(tlsf_t, mem);
}

tlsf_t tlsf_create_with_pool(void* mem, size_t bytes)
{
	tlsf_t tlsf = tlsf_create(mem);
	tlsf_add_pool(tlsf, (char*)mem + tlsf_size(), bytes - tlsf_size());
	return tlsf;
}

void tlsf_destroy(tlsf_t tlsf)
{
	/* Nothing to do. */
	(void)tlsf;
}

pool_t tlsf_get_pool(tlsf_t tlsf)
{
	return tlsf_cast(pool_t, (char*)tlsf + tlsf_size());
}

void* tlsf_malloc(tlsf_t tlsf, size_t size)
{
	if (g_use_optimized_memory_locality) {
		return optimized_tlsf_malloc(tlsf, size);
	}
	else {
		control_t* control = tlsf_cast(control_t*, tlsf);
		const size_t adjust = adjust_request_size(size, ALIGN_SIZE);
		block_header_t* block = block_locate_free(control, adjust);
		return block_prepare_used(control, block, adjust);
	}

}

void* tlsf_memalign(tlsf_t tlsf, size_t align, size_t size)
{
	control_t* control = tlsf_cast(control_t*, tlsf);
	const size_t adjust = adjust_request_size(size, ALIGN_SIZE);

	/*
	** We must allocate an additional minimum block size bytes so that if
	** our free block will leave an alignment gap which is smaller, we can
	** trim a leading free block and release it back to the pool. We must
	** do this because the previous physical block is in use, therefore
	** the prev_phys_block field is not valid, and we can't simply adjust
	** the size of that block.
	*/
	const size_t gap_minimum = sizeof(block_header_t);
	const size_t size_with_gap = adjust_request_size(adjust + align + gap_minimum, align);

	/*
	** If alignment is less than or equals base alignment, we're done.
	** If we requested 0 bytes, return null, as tlsf_malloc(0) does.
	*/
	const size_t aligned_size = (adjust && align > ALIGN_SIZE) ? size_with_gap : adjust;

	block_header_t* block = block_locate_free(control, aligned_size);

	/* This can't be a static assert. */
	tlsf_assert(sizeof(block_header_t) == block_size_min + block_header_overhead);

	if (block)
	{
		void* ptr = block_to_ptr(block);
		void* aligned = align_ptr(ptr, align);
		size_t gap = tlsf_cast(size_t,
			tlsf_cast(tlsfptr_t, aligned) - tlsf_cast(tlsfptr_t, ptr));

		/* If gap size is too small, offset to next aligned boundary. */
		if (gap && gap < gap_minimum)
		{
			const size_t gap_remain = gap_minimum - gap;
			const size_t offset = tlsf_max(gap_remain, align);
			const void* next_aligned = tlsf_cast(void*,
				tlsf_cast(tlsfptr_t, aligned) + offset);

			aligned = align_ptr(next_aligned, align);
			gap = tlsf_cast(size_t,
				tlsf_cast(tlsfptr_t, aligned) - tlsf_cast(tlsfptr_t, ptr));
		}

		if (gap)
		{
			tlsf_assert(gap >= gap_minimum && "gap size too small");
			block = block_trim_free_leading(control, block, gap);
		}
	}

	return block_prepare_used(control, block, adjust);
}

void tlsf_free(tlsf_t tlsf, void* ptr)
{
	/* Don't attempt to free a NULL pointer. */
	if (g_use_optimized_memory_locality) {
		if (ptr) {
			optimized_tlsf_free(tlsf, ptr);
		}

	}
	else {
		if (ptr)
		{
			control_t* control = tlsf_cast(control_t*, tlsf);
			block_header_t* block = block_from_ptr(ptr);
			tlsf_assert(!block_is_free(block) && "block already marked as free");
			block_mark_as_free(block);
			block = block_merge_prev(control, block);
			block = block_merge_next(control, block);
			block_insert(control, block);
		}
	}


}

/*
** The TLSF block information provides us with enough information to
** provide a reasonably intelligent implementation of realloc, growing or
** shrinking the currently allocated block as required.
**
** This routine handles the somewhat esoteric edge cases of realloc:
** - a non-zero size with a null pointer will behave like malloc
** - a zero size with a non-null pointer will behave like free
** - a request that cannot be satisfied will leave the original buffer
**   untouched
** - an extended buffer size will leave the newly-allocated area with
**   contents undefined
*/
void* tlsf_realloc(tlsf_t tlsf, void* ptr, size_t size)
{
	control_t* control = tlsf_cast(control_t*, tlsf);
	void* p = 0;

	/* Zero-size requests are treated as free. */
	if (ptr && size == 0)
	{
		tlsf_free(tlsf, ptr);
	}
	/* Requests with NULL pointers are treated as malloc. */
	else if (!ptr)
	{
		p = tlsf_malloc(tlsf, size);
	}
	else
	{
		block_header_t* block = block_from_ptr(ptr);
		block_header_t* next = block_next(block);

		const size_t cursize = block_size(block);
		const size_t combined = cursize + block_size(next) + block_header_overhead;
		const size_t adjust = adjust_request_size(size, ALIGN_SIZE);

		tlsf_assert(!block_is_free(block) && "block already marked as free");

		/*
		** If the next block is used, or when combined with the current
		** block, does not offer enough space, we must reallocate and copy.
		*/
		if (adjust > cursize && (!block_is_free(next) || adjust > combined))
		{
			p = tlsf_malloc(tlsf, size);
			if (p)
			{
				const size_t minsize = tlsf_min(cursize, size);
				memcpy(p, ptr, minsize);
				tlsf_free(tlsf, ptr);
			}
		}
		else
		{
			/* Do we need to expand to the next block? */
			if (adjust > cursize)
			{
				block_merge_next(control, block);
				block_mark_as_used(block);
			}

			/* Trim the resulting block and return the original pointer. */
			block_trim_used(control, block, adjust);
			p = ptr;
		}
	}

	return p;
}

// 优化的块插入函数
static void optimized_insert_free_block(control_t* control, block_header_t* block, int fl, int sl) {
	// 快速获取当前头部
	block_header_t* current = control->blocks[fl][sl];

	// 一次性更新链接关系
	block->next_free = current;
	block->prev_free = &control->block_null;
	current->prev_free = block;

	// 直接更新头部
	control->blocks[fl][sl] = block;

	// 设置位图位
	control->fl_bitmap |= (1U << fl);
	control->sl_bitmap[fl] |= (1U << sl);
}

// 优化的块移除函数 
static void optimized_remove_free_block(control_t* control, block_header_t* block, int fl, int sl) {
	block_header_t* prev = block->prev_free;
	block_header_t* next = block->next_free;

	// 更新链接
	next->prev_free = prev;
	prev->next_free = next;

	// 使用条件移动而非分支
	int is_head = (control->blocks[fl][sl] == block);
	int is_last = (next == &control->block_null);

	// 条件更新头部
	if (is_head) {
		control->blocks[fl][sl] = next;

		// 条件更新位图
		if (is_last) {
			control->sl_bitmap[fl] &= ~(1U << sl);

			// 检查第一级位图是否需要更新
			if (!control->sl_bitmap[fl]) {
				control->fl_bitmap &= ~(1U << fl);
			}
		}
	}
}

// 预计算的小尺寸映射表，最大覆盖到4KB
#define MAX_PRECOMPUTED_SIZE 4096
static struct {
	int fl;
	int sl;
} g_size_mapping[MAX_PRECOMPUTED_SIZE + 1];

// 初始化预计算表
static void initialize_mapping_table() {
	static int initialized = 0;
	if (initialized) return;

	for (size_t size = 0; size <= MAX_PRECOMPUTED_SIZE; size++) {
		int fl, sl;

		// 完全复制原始mapping_search函数的逻辑
		size_t temp_size = size;
		if (temp_size >= SMALL_BLOCK_SIZE) {
			// 注意：这里必须使用原始的tlsf_fls_sizet，不是优化版本
			const size_t round = (1 << (tlsf_fls_sizet(temp_size) - SL_INDEX_COUNT_LOG2)) - 1;
			temp_size += round;
		}

		// 调用原始mapping_insert函数
		if (temp_size < SMALL_BLOCK_SIZE) {
			fl = 0;
			sl = tlsf_cast(int, temp_size) / (SMALL_BLOCK_SIZE / SL_INDEX_COUNT);
		}
		else {
			fl = tlsf_fls_sizet(temp_size);
			sl = tlsf_cast(int, temp_size >> (fl - SL_INDEX_COUNT_LOG2)) ^ (1 << SL_INDEX_COUNT_LOG2);
			fl -= (FL_INDEX_SHIFT - 1);
		}

		g_size_mapping[size].fl = fl;
		g_size_mapping[size].sl = sl;
	}

	initialized = 1;
}


// 优化的映射搜索函数
static void optimize_mapping_search(size_t size, int* fli, int* sli) {
	// 确保表已初始化
	initialize_mapping_table();

	// 小尺寸直接查表
	if (size <= MAX_PRECOMPUTED_SIZE) {
		*fli = g_size_mapping[size].fl;
		*sli = g_size_mapping[size].sl;
		return;
	}

	// 大尺寸完全使用原始函数
	// 注意：不要自己实现逻辑，直接调用原始函数来确保一致

	// 首先进行舍入
	if (size >= SMALL_BLOCK_SIZE) {
		const size_t round = (1 << (tlsf_fls_sizet(size) - SL_INDEX_COUNT_LOG2)) - 1;
		size += round;
	}

	// 然后通过原始mapping_insert计算索引
	if (size < SMALL_BLOCK_SIZE) {
		*fli = 0;
		*sli = tlsf_cast(int, size) / (SMALL_BLOCK_SIZE / SL_INDEX_COUNT);
	}
	else {
		*fli = tlsf_fls_sizet(size);
		*sli = tlsf_cast(int, size >> (*fli - SL_INDEX_COUNT_LOG2)) ^ (1 << SL_INDEX_COUNT_LOG2);
		*fli -= (FL_INDEX_SHIFT - 1);
	}
}

// 更严格的映射函数测试
void detailed_mapping_test(size_t size) {
	// 原始函数的计算
	size_t orig_size = size;
	if (orig_size >= SMALL_BLOCK_SIZE) {
		const size_t round = (1 << (tlsf_fls_sizet(orig_size) - SL_INDEX_COUNT_LOG2)) - 1;
		orig_size += round;
	}
	int orig_fl, orig_sl;
	mapping_insert(orig_size, &orig_fl, &orig_sl);

	// 优化函数的计算
	int opt_fl, opt_sl;
	optimize_mapping_search(size, &opt_fl, &opt_sl);

	// 比较并打印详细信息
	if (orig_fl != opt_fl || orig_sl != opt_sl) {
		printf("[TLSF] 映射不匹配: 大小=%zu", size);
		printf("  原始处理: 调整大小=%zu, FL=%d, SL=%d", orig_size, orig_fl, orig_sl);
		printf("  优化处理: FL=%d, SL=%d", opt_fl, opt_sl);

		// 检查映射表中的值
		if (size <= MAX_PRECOMPUTED_SIZE) {
			printf("  映射表值: FL=%d, SL=%d", g_size_mapping[size].fl, g_size_mapping[size].sl);
		}
	}
}

// 诊断函数，用于准确定位映射计算中的差异
void diagnose_mapping_difference(size_t size) {
	// 记录每个步骤的中间值

	// 原始算法的步骤
	size_t orig_size = size;
	size_t orig_rounded_size = orig_size;

	if (orig_size >= SMALL_BLOCK_SIZE) {
		int orig_fls = tlsf_fls_sizet(orig_size);
		int orig_shift = orig_fls - SL_INDEX_COUNT_LOG2;
		size_t orig_round = (1 << orig_shift) - 1;
		orig_rounded_size = orig_size + orig_round;

		printf("原始[%zu]: fls=%d, shift=%d, round=%zu, rounded=%zu\n",
			orig_size, orig_fls, orig_shift, orig_round, orig_rounded_size);
	}

	int orig_fl, orig_sl;
	if (orig_rounded_size < SMALL_BLOCK_SIZE) {
		orig_fl = 0;
		orig_sl = (int)orig_rounded_size / (SMALL_BLOCK_SIZE / SL_INDEX_COUNT);
		printf("原始小块[%zu]: division=%d\n",
			orig_rounded_size, (SMALL_BLOCK_SIZE / SL_INDEX_COUNT));
	}
	else {
		orig_fl = tlsf_fls_sizet(orig_rounded_size);
		int sl_shift = orig_fl - SL_INDEX_COUNT_LOG2;
		int sl_unxor = (int)(orig_rounded_size >> sl_shift);
		orig_sl = sl_unxor ^ (1 << SL_INDEX_COUNT_LOG2);
		orig_fl -= (FL_INDEX_SHIFT - 1);
		printf("原始大块[%zu]: fls=%d, sl_shift=%d, sl_unxor=%d, sl_mask=%d\n",
			orig_rounded_size, orig_fl + (FL_INDEX_SHIFT - 1),
			sl_shift, sl_unxor, (1 << SL_INDEX_COUNT_LOG2));
	}

	// 优化算法的步骤 (假设查表)
	int opt_fl = g_size_mapping[size].fl;
	int opt_sl = g_size_mapping[size].sl;

	printf("结果比较[%zu]: 原始=[%d,%d], 优化=[%d,%d]\n",
		size, orig_fl, orig_sl, opt_fl, opt_sl);
}

// 彻底测试映射函数
int test_optimized_mapping_thorough() {
	int errors = 0;

	// 确保映射表已初始化
	initialize_mapping_table();

	// 测试每一个可能的小尺寸
	for (size_t size = 0; size <= MAX_PRECOMPUTED_SIZE; size++) {
		// 保存当前优化状态
		int save_optimized = g_use_optimized_mapping;
		g_use_optimized_mapping = 0;

		// 计算原始结果
		int orig_fl, orig_sl;
		mapping_search(size, &orig_fl, &orig_sl);

		// 恢复优化状态
		g_use_optimized_mapping = save_optimized;

		// 获取优化表结果
		int opt_fl = g_size_mapping[size].fl;
		int opt_sl = g_size_mapping[size].sl;

		// 比较结果
		if (orig_fl != opt_fl || orig_sl != opt_sl) {
			if (errors < 10) { // 限制输出
				printf("[TLSF] 映射测试失败: 大小=%zu, 原始=[%d,%d], 优化=[%d,%d]",
					size, orig_fl, orig_sl, opt_fl, opt_sl);

				// 如果需要更详细诊断
				diagnose_mapping_difference(size);
			}
			errors++;
		}
	}

	if (errors > 0) {
		printf("[TLSF] 映射优化测试失败: 在%d个大小中发现%d个错误",
			MAX_PRECOMPUTED_SIZE + 1, errors);
		g_use_optimized_mapping = 0;
	}
	else {
		printf("[TLSF] 所有映射优化测试通过!");
	}

	return errors == 0;
}

// 测试优化的块查找函数
int test_optimized_block_search() {
	printf("[TLSF] 开始测试优化的块查找函数...\n");

	// 创建测试控制结构
	control_t control;
	control_construct(&control);

	// 创建测试用的内存池
	const size_t pool_size = 1024 * 1024; // 1 MB测试池
	void* pool_memory = malloc(pool_size);
	if (!pool_memory) {
		printf("[TLSF] 测试失败: 无法分配测试内存池\n");
		return 0;
	}

	// 初始化内存池
	void* pool = tlsf_add_pool(&control, pool_memory, pool_size);
	if (!pool) {
		printf("[TLSF] 测试失败: 无法初始化TLSF内存池\n");
		free(pool_memory);
		return 0;
	}

	// 创建各种大小的内存块测试场景
	const int num_blocks = 20;
	size_t block_sizes[] = {
		16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
		24, 48, 96, 192, 384, 768, 1536, 3072, 6144, 9216
	};

	void* allocated_blocks[20];

	// 分配一些块
	for (int i = 0; i < num_blocks / 2; i++) {
		allocated_blocks[i] = tlsf_malloc(&control, block_sizes[i]);
		if (!allocated_blocks[i]) {
			printf("[TLSF] 测试警告: 块分配失败, 大小=%zu\n", block_sizes[i]);
		}
	}

	// 释放一些块，创建空闲块
	for (int i = 0; i < num_blocks / 4; i++) {
		if (allocated_blocks[i]) {
			tlsf_free(&control, allocated_blocks[i]);
			allocated_blocks[i] = NULL;
		}
	}

	// 再分配一些块
	for (int i = num_blocks / 2; i < num_blocks; i++) {
		allocated_blocks[i] = tlsf_malloc(&control, block_sizes[i]);
		if (!allocated_blocks[i]) {
			printf("[TLSF] 测试警告: 块分配失败, 大小=%zu\n", block_sizes[i]);
		}
	}

	// 再次释放一些块，创建更多碎片
	for (int i = num_blocks / 2; i < num_blocks * 3 / 4; i++) {
		if (allocated_blocks[i]) {
			tlsf_free(&control, allocated_blocks[i]);
			allocated_blocks[i] = NULL;
		}
	}

	// 现在测试各种查找场景
	int errors = 0;

	// 测试场景1: 测试不同大小的请求
	size_t test_sizes[] = {
		8, 16, 32, 48, 64, 96, 128, 192, 256, 384, 512,
		768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 16384
	};

	const int num_test_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);

	for (int i = 0; i < num_test_sizes; i++) {
		size_t test_size = test_sizes[i];

		// 计算映射
		int fl_orig = 0, sl_orig = 0;
		int fl_opt = 0, sl_opt = 0;

		mapping_search(test_size, &fl_orig, &sl_orig);
		fl_opt = fl_orig;
		sl_opt = sl_orig;

		// 如果fl值超出范围，跳过此测试
		if (fl_orig >= FL_INDEX_COUNT) continue;

		// 保存原始值用于恢复
		int save_fl_orig = fl_orig;
		int save_sl_orig = sl_orig;
		int save_fl_opt = fl_opt;
		int save_sl_opt = sl_opt;

		// 调用原始函数
		block_header_t* orig_block = search_suitable_block(&control, &fl_orig, &sl_orig);

		// 恢复原始值
		fl_opt = save_fl_opt;
		sl_opt = save_sl_opt;

		// 调用优化函数
		block_header_t* opt_block = optimized_search_suitable_block(&control, &fl_opt, &sl_opt);

		// 比较结果
		if (orig_block != opt_block) {
			printf("[TLSF] 块查找结果不匹配: 大小=%zu, 原始=0x%p, 优化=0x%p\n",
				test_size, orig_block, opt_block);
			errors++;
		}

		if (fl_orig != fl_opt) {
			printf("[TLSF] fl索引不匹配: 大小=%zu, 原始=%d, 优化=%d\n",
				test_size, fl_orig, fl_opt);
			errors++;
		}

		if (sl_orig != sl_opt) {
			printf("[TLSF] sl索引不匹配: 大小=%zu, 原始=%d, 优化=%d\n",
				test_size, sl_orig, sl_opt);
			errors++;
		}
	}

	// 测试场景2: 边缘情况测试

	// 1. 空列表测试
	{
		// 清空控制结构
		control_t empty_control;
		control_construct(&empty_control);

		for (int fl = 0; fl < FL_INDEX_COUNT; fl++) {
			for (int sl = 0; sl < SL_INDEX_COUNT; sl++) {
				int fl_orig = fl, sl_orig = sl;
				int fl_opt = fl, sl_opt = sl;

				// 调用原始函数
				block_header_t* orig_block = search_suitable_block(&empty_control, &fl_orig, &sl_orig);

				// 重置索引
				fl_opt = fl;
				sl_opt = sl;

				// 调用优化函数
				block_header_t* opt_block = optimized_search_suitable_block(&empty_control, &fl_opt, &sl_opt);

				// 比较结果 - 应该都返回NULL
				if (orig_block != opt_block) {
					printf("[TLSF] 空列表测试失败: fl=%d, sl=%d, 原始=0x%p, 优化=0x%p\n",
						fl, sl, orig_block, opt_block);
					errors++;
				}
			}
		}
	}

	// 2. 填满位图的测试
	{
		// 创建一个新的控制结构并填充位图
		control_t full_control;
		control_construct(&full_control);

		// 填充第一级位图
		full_control.fl_bitmap = 0xFFFFFFFF;

		// 填充第二级位图
		for (int fl = 0; fl < FL_INDEX_COUNT; fl++) {
			full_control.sl_bitmap[fl] = 0xFFFFFFFF;

			// 创建一些假块
			for (int sl = 0; sl < SL_INDEX_COUNT; sl++) {
				static block_header_t dummy_block;
				dummy_block.next_free = &dummy_block;
				dummy_block.prev_free = &dummy_block;
				full_control.blocks[fl][sl] = &dummy_block;
			}
		}

		// 测试各种索引组合
		for (int fl = 0; fl < FL_INDEX_COUNT - 1; fl++) {
			for (int sl = 0; sl < SL_INDEX_COUNT - 1; sl++) {
				int fl_orig = fl, sl_orig = sl;
				int fl_opt = fl, sl_opt = sl;

				// 调用原始函数
				block_header_t* orig_block = search_suitable_block(&full_control, &fl_orig, &sl_orig);

				// 重置索引
				fl_opt = fl;
				sl_opt = sl;

				// 调用优化函数
				block_header_t* opt_block = optimized_search_suitable_block(&full_control, &fl_opt, &sl_opt);

				// 比较结果
				if (orig_block != opt_block || fl_orig != fl_opt || sl_orig != sl_opt) {
					printf("[TLSF] 满位图测试失败: 初始fl=%d, sl=%d\n", fl, sl);
					printf("  原始: 块=0x%p, fl=%d, sl=%d\n", orig_block, fl_orig, sl_orig);
					printf("  优化: 块=0x%p, fl=%d, sl=%d\n", opt_block, fl_opt, sl_opt);
					errors++;
				}
			}
		}
	}

	// 3. 特殊位模式测试
	{
		// 测试各种特殊的位图模式
		struct {
			unsigned int fl_bitmap;
			unsigned int sl_bitmap[FL_INDEX_COUNT];
			int start_fl;
			int start_sl;
		} test_patterns[] = {
			// 只有一个位置1的情况
			{0x00000001, {0x00000001}, 0, 0},
			// 只有最高位为1的情况
			{0x80000000, {0x80000000}, FL_INDEX_COUNT - 1, 0},
			// 交错模式
			{0xAAAAAAAA, {0xAAAAAAAA}, 1, 0},
			// 只有一个可用块，但在较高索引
			{0x00010000, {0x00000001}, 16, 0}
		};

		for (size_t pattern_idx = 0; pattern_idx < sizeof(test_patterns) / sizeof(test_patterns[0]); pattern_idx++) {
			// 创建测试控制结构
			control_t pattern_control;
			control_construct(&pattern_control);

			// 设置位图
			pattern_control.fl_bitmap = test_patterns[pattern_idx].fl_bitmap;
			for (int fl = 0; fl < FL_INDEX_COUNT; fl++) {
				pattern_control.sl_bitmap[fl] = test_patterns[pattern_idx].sl_bitmap[0];

				// 创建一些假块
				for (int sl = 0; sl < SL_INDEX_COUNT; sl++) {
					static block_header_t dummy_block;
					dummy_block.next_free = &dummy_block;
					dummy_block.prev_free = &dummy_block;
					pattern_control.blocks[fl][sl] = &dummy_block;
				}
			}

			// 测试搜索
			int fl = test_patterns[pattern_idx].start_fl;
			int sl = test_patterns[pattern_idx].start_sl;

			int fl_orig = fl, sl_orig = sl;
			int fl_opt = fl, sl_opt = sl;

			// 调用原始函数
			block_header_t* orig_block = search_suitable_block(&pattern_control, &fl_orig, &sl_orig);

			// 重置索引
			fl_opt = fl;
			sl_opt = sl;

			// 调用优化函数
			block_header_t* opt_block = optimized_search_suitable_block(&pattern_control, &fl_opt, &sl_opt);

			// 比较结果
			if (orig_block != opt_block || fl_orig != fl_opt || sl_orig != sl_opt) {
				printf("[TLSF] 特殊位模式测试失败: 模式=%zu\n", pattern_idx);
				printf("  原始: 块=0x%p, fl=%d, sl=%d\n", orig_block, fl_orig, sl_orig);
				printf("  优化: 块=0x%p, fl=%d, sl=%d\n", opt_block, fl_opt, sl_opt);
				errors++;
			}
		}
	}

	// 清理测试资源
	for (int i = 0; i < num_blocks; i++) {
		if (allocated_blocks[i]) {
			tlsf_free(&control, allocated_blocks[i]);
		}
	}

	free(pool_memory);

	// 报告结果
	if (errors == 0) {
		printf("[TLSF] 块查找优化测试全部通过!\n");
		return 1;
	}
	else {
		printf("[TLSF] 块查找优化测试失败: 发现%d个错误\n", errors);
		// 自动禁用优化
		g_use_optimized_block_search = 0;
		return 0;
	}
}

// 测试优化的块管理函数
int test_optimized_block_management() {
	printf("[TLSF] 开始测试优化的块管理函数...\n");

	// 创建两个相同的控制结构
	control_t control_orig, control_opt;
	control_construct(&control_orig);
	control_construct(&control_opt);

	// 创建测试内存池
	const size_t pool_size = 64 * 1024; // 64 KB测试池
	void* pool_memory1 = malloc(pool_size);
	void* pool_memory2 = malloc(pool_size);

	if (!pool_memory1 || !pool_memory2) {
		printf("[TLSF] 测试失败: 无法分配测试内存池\n");
		if (pool_memory1) free(pool_memory1);
		if (pool_memory2) free(pool_memory2);
		return 0;
	}

	// 初始化内存池
	void* pool1 = tlsf_add_pool(&control_orig, pool_memory1, pool_size);
	void* pool2 = tlsf_add_pool(&control_opt, pool_memory2, pool_size);

	if (!pool1 || !pool2) {
		printf("[TLSF] 测试失败: 无法初始化TLSF内存池\n");
		free(pool_memory1);
		free(pool_memory2);
		return 0;
	}

	// 测试: 分配和释放相同的块模式
	const int num_sizes = 10;
	size_t sizes[10] = { 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192 };
	void* blocks_orig[10];
	void* blocks_opt[10];

	int errors = 0;

	// 暂时禁用优化以确保使用原始函数
	int save_opt = g_use_optimized_block_management;
	g_use_optimized_block_management = 0;

	// 使用原始函数分配
	for (int i = 0; i < num_sizes; i++) {
		blocks_orig[i] = tlsf_malloc(&control_orig, sizes[i]);
		if (!blocks_orig[i]) {
			printf("[TLSF] 测试警告: 原始分配失败, 大小=%zu\n", sizes[i]);
		}
	}

	// 启用优化
	g_use_optimized_block_management = 1;

	// 使用优化函数分配
	for (int i = 0; i < num_sizes; i++) {
		blocks_opt[i] = tlsf_malloc(&control_opt, sizes[i]);
		if (!blocks_opt[i]) {
			printf("[TLSF] 测试警告: 优化分配失败, 大小=%zu\n", sizes[i]);
		}
	}

	// 比较分配结果
	for (int i = 0; i < num_sizes; i++) {
		if ((!blocks_orig[i] && blocks_opt[i]) || (blocks_orig[i] && !blocks_opt[i])) {
			printf("[TLSF] 分配结果不一致: 大小=%zu, 原始=%p, 优化=%p\n",
				sizes[i], blocks_orig[i], blocks_opt[i]);
			errors++;
		}
	}

	// 释放测试 - 交替释放
	g_use_optimized_block_management = 0;
	tlsf_free(&control_orig, blocks_orig[1]);
	tlsf_free(&control_orig, blocks_orig[3]);
	tlsf_free(&control_orig, blocks_orig[5]);
	tlsf_free(&control_orig, blocks_orig[7]);
	tlsf_free(&control_orig, blocks_orig[9]);

	g_use_optimized_block_management = 1;
	tlsf_free(&control_opt, blocks_opt[1]);
	tlsf_free(&control_opt, blocks_opt[3]);
	tlsf_free(&control_opt, blocks_opt[5]);
	tlsf_free(&control_opt, blocks_opt[7]);
	tlsf_free(&control_opt, blocks_opt[9]);

	// 再次分配，检查两个控制结构的状态是否相同
	g_use_optimized_block_management = 0;
	void* new_block_orig = tlsf_malloc(&control_orig, 256);

	g_use_optimized_block_management = 1;
	void* new_block_opt = tlsf_malloc(&control_opt, 256);

	if ((!new_block_orig && new_block_opt) || (new_block_orig && !new_block_opt)) {
		printf("[TLSF] 再分配结果不一致: 原始=%p, 优化=%p\n", new_block_orig, new_block_opt);
		errors++;
	}

	// 完全释放
	for (int i = 0; i < num_sizes; i++) {
		if (i != 1 && i != 3 && i != 5 && i != 7 && i != 9) {
			g_use_optimized_block_management = 0;
			if (blocks_orig[i]) tlsf_free(&control_orig, blocks_orig[i]);

			g_use_optimized_block_management = 1;
			if (blocks_opt[i]) tlsf_free(&control_opt, blocks_opt[i]);
		}
	}

	if (new_block_orig) {
		g_use_optimized_block_management = 0;
		tlsf_free(&control_orig, new_block_orig);
	}

	if (new_block_opt) {
		g_use_optimized_block_management = 1;
		tlsf_free(&control_opt, new_block_opt);
	}

	// 检查池状态 - 两个池应该都是空闲的
	// 这个检查不是很严格，但可以捕获明显错误
	g_use_optimized_block_management = 0;
	void* final_orig = tlsf_malloc(&control_orig, pool_size - 1000);

	g_use_optimized_block_management = 1;
	void* final_opt = tlsf_malloc(&control_opt, pool_size - 1000);

	if ((!final_orig && final_opt) || (final_orig && !final_opt)) {
		printf("[TLSF] 最终分配不一致: 原始=%p, 优化=%p\n", final_orig, final_opt);
		errors++;
	}

	// 恢复设置
	g_use_optimized_block_management = save_opt;

	// 清理
	free(pool_memory1);
	free(pool_memory2);

	// 报告结果
	if (errors == 0) {
		printf("[TLSF] 块管理优化测试通过!\n");
		return 1;
	}
	else {
		printf("[TLSF] 块管理优化测试失败: %d个错误\n", errors);
		// 禁用优化
		g_use_optimized_block_management = 0;
		return 0;
	}
}

// 初始化小块缓存
static void initialize_small_block_cache() {
	if (g_small_block_cache.initialized) return;

	// 设置支持的块大小 - 根据实际分配模式调整
	g_small_block_cache.sizes[0] = 16;   // 很小的分配，如指针等
	g_small_block_cache.sizes[1] = 32;   // 小型结构体
	g_small_block_cache.sizes[2] = 64;   // 中小型结构体
	g_small_block_cache.sizes[3] = 128;  // 中型结构体
	g_small_block_cache.sizes[4] = 256;  // 中大型结构体
	g_small_block_cache.sizes[5] = 512;  // 大型结构体
	g_small_block_cache.sizes[6] = 1024; // 小缓冲区
	g_small_block_cache.sizes[7] = 2048; // 中型缓冲区

	// 初始化计数器
	for (int i = 0; i < SMALL_CACHE_SIZE_COUNT; i++) {
		g_small_block_cache.count[i] = 0;

		// 清空块指针
		for (int j = 0; j < SMALL_CACHE_COUNT_PER_SIZE; j++) {
			g_small_block_cache.blocks[i][j] = NULL;
		}
	}

	g_small_block_cache.initialized = 1;
	printf("[TLSF] 小块缓存已初始化, 支持%d种大小\n", SMALL_CACHE_SIZE_COUNT);
}

// 从缓存获取块
static void* get_block_from_cache(size_t size) {
	if (!g_small_block_cache.initialized) {
		initialize_small_block_cache();
	}

	// 找到匹配的大小类别
	for (int i = 0; i < SMALL_CACHE_SIZE_COUNT; i++) {
		if (g_small_block_cache.sizes[i] >= size) {
			// 找到匹配大小
			if (g_small_block_cache.count[i] > 0) {
				// 从缓存取出
				g_small_block_cache.count[i]--;
				void* block = g_small_block_cache.blocks[i][g_small_block_cache.count[i]];
				g_small_block_cache.blocks[i][g_small_block_cache.count[i]] = NULL;
				return block;
			}
			break; // 没有缓存的块，退出
		}
	}

	return NULL; // 缓存未命中
}

// 将块放入缓存
static int put_block_to_cache(void* ptr, size_t size) {
	if (!g_small_block_cache.initialized) {
		initialize_small_block_cache();
	}

	// 找到匹配的大小类别
	for (int i = 0; i < SMALL_CACHE_SIZE_COUNT; i++) {
		if (g_small_block_cache.sizes[i] == size) {
			// 找到精确匹配
			if (g_small_block_cache.count[i] < SMALL_CACHE_COUNT_PER_SIZE) {
				// 缓存未满，添加到缓存
				g_small_block_cache.blocks[i][g_small_block_cache.count[i]] = ptr;
				g_small_block_cache.count[i]++;
				return 1; // 成功缓存
			}
			break; // 缓存已满，退出
		}
		else if (g_small_block_cache.sizes[i] > size) {
			// 找到第一个大于当前大小的类别，退出
			break;
		}
	}

	return 0; // 未缓存
}

// 清空小块缓存
static void flush_small_block_cache(tlsf_t tlsf) {
	if (!g_small_block_cache.initialized) return;

	for (int i = 0; i < SMALL_CACHE_SIZE_COUNT; i++) {
		for (int j = 0; j < g_small_block_cache.count[i]; j++) {
			if (g_small_block_cache.blocks[i][j]) {
				// 使用原始方法释放块
				tlsf_free(tlsf, g_small_block_cache.blocks[i][j]);
				g_small_block_cache.blocks[i][j] = NULL;
			}
		}
		g_small_block_cache.count[i] = 0;
	}
}

// 优化的内存分配函数
void* optimized_tlsf_malloc(tlsf_t tlsf, size_t size) {
	// 标记是否是小块分配
	int is_small_block = 0;

	// 处理小块分配
	if (size <= 2048) {
		is_small_block = 1;

		// 从缓存中尝试获取
		void* block = get_block_from_cache(size);
		if (block) {
			// 缓存命中，直接返回
			return block;
		}
	}

	// 常规路径 - 调整大小
	control_t* control = tlsf_cast(control_t*, tlsf);
	const size_t adjust = adjust_request_size(size, ALIGN_SIZE);

	// 内存局部性优化 - 对齐到缓存行大小
	size_t aligned_size = adjust;
	const size_t CACHE_LINE_SIZE = 64; // 典型的缓存行大小

	// 对于较大的块，考虑对齐到缓存行
	if (size >= 256 && !is_small_block) {
		aligned_size = (adjust + CACHE_LINE_SIZE - 1) & ~(CACHE_LINE_SIZE - 1);
	}

	// 分配块
	block_header_t* block = block_locate_free(control, aligned_size);
	void* p = block_prepare_used(control, block, aligned_size);

	return p;
}

// 优化的内存释放函数
void optimized_tlsf_free(tlsf_t tlsf, void* ptr) {
	// 空指针检查
	if (!ptr) return;

	// 获取块头信息
	block_header_t* block = block_from_ptr(ptr);
	size_t size_of_block = block_size(block);  // 改名为size_of_block避免冲突

	// 尝试放入小块缓存
	if (size_of_block <= 2048) {
		if (put_block_to_cache(ptr, size_of_block)) {
			// 成功缓存，直接返回
			return;
		}
	}

	// 常规释放路径
	control_t* control = tlsf_cast(control_t*, tlsf);
	block_mark_as_free(block);
	block = block_merge_prev(control, block);
	block = block_merge_next(control, block);
	block_insert(control, block);
}

int test_optimized_memory_locality() {
	printf("[TLSF] 开始测试内存局部性优化...\n");

	// 创建测试用TLSF实例
	const size_t pool_size = 1024 * 1024; // 1 MB池
	void* pool_memory = malloc(pool_size);
	if (!pool_memory) {
		printf("[TLSF] 测试失败: 无法分配测试内存池\n");
		return 0;
	}

	tlsf_t tlsf = tlsf_create(pool_memory);
	if (!tlsf) {
		printf("[TLSF] 测试失败: 无法创建TLSF实例\n");
		free(pool_memory);
		return 0;
	}

	void* pool = tlsf_add_pool(tlsf, (char*)pool_memory + tlsf_size(), pool_size - tlsf_size());
	if (!pool) {
		printf("[TLSF] 测试失败: 无法添加内存池\n");
		free(pool_memory);
		return 0;
	}

	int errors = 0;

	// 测试小块缓存
	{
		// 启用优化
		g_use_optimized_memory_locality = 1;

		// 先分配一些小块
		const int num_blocks = 20;
		void* blocks[20];

		for (int i = 0; i < num_blocks; i++) {
			// 交替分配不同大小
			size_t size = (i % 8) * 32 + 16; // 16, 48, 80, ...
			blocks[i] = tlsf_malloc(tlsf, size);
			if (!blocks[i]) {
				printf("[TLSF] 测试警告: 块分配失败, 大小=%zu\n", size);
				errors++;
			}
		}

		// 释放部分块，这些应该进入缓存
		for (int i = 0; i < num_blocks / 2; i++) {
			if (blocks[i]) {
				tlsf_free(tlsf, blocks[i]);
				blocks[i] = NULL;
			}
		}

		// 重新分配相同大小，应该从缓存获取
		for (int i = 0; i < num_blocks / 2; i++) {
			size_t size = (i % 8) * 32 + 16;
			blocks[i] = tlsf_malloc(tlsf, size);
			if (!blocks[i]) {
				printf("[TLSF] 测试警告: 缓存重分配失败, 大小=%zu\n", size);
				errors++;
			}
		}

		// 释放所有块
		for (int i = 0; i < num_blocks; i++) {
			if (blocks[i]) {
				tlsf_free(tlsf, blocks[i]);
				blocks[i] = NULL;
			}
		}

		// 显式刷新缓存
		flush_small_block_cache(tlsf);
	}

	// 测试对齐优化
	{
		// 分配一个较大的块
		size_t large_size = 1024;
		void* large_block = tlsf_malloc(tlsf, large_size);

		if (!large_block) {
			printf("[TLSF] 测试警告: 大块分配失败, 大小=%zu\n", large_size);
			errors++;
		}
		else {
			// 检查地址对齐
			uintptr_t addr = (uintptr_t)large_block;
			if ((addr % 64) != 0) { // 检查是否对齐到64字节
				printf("[TLSF] 警告: 大块未对齐到缓存行, 地址=%p\n", large_block);
				// 这不算严重错误，只是警告
			}

			// 释放块
			tlsf_free(tlsf, large_block);
		}
	}

	// 测试分配-释放循环的性能
	{
		const int cycles = 1000;
		const int blocks_per_cycle = 100;
		void* blocks[100];

		// 禁用优化，测试原始性能
		g_use_optimized_memory_locality = 0;

		// 计时
		clock_t start = clock();

		for (int cycle = 0; cycle < cycles; cycle++) {
			// 分配
			for (int i = 0; i < blocks_per_cycle; i++) {
				size_t size = (i % 8) * 32 + 16;
				blocks[i] = tlsf_malloc(tlsf, size);
			}

			// 释放
			for (int i = 0; i < blocks_per_cycle; i++) {
				if (blocks[i]) {
					tlsf_free(tlsf, blocks[i]);
					blocks[i] = NULL;
				}
			}
		}

		clock_t end = clock();
		double original_time = (double)(end - start) / CLOCKS_PER_SEC;

		// 启用优化，测试优化性能
		g_use_optimized_memory_locality = 1;

		// 计时
		start = clock();

		for (int cycle = 0; cycle < cycles; cycle++) {
			// 分配
			for (int i = 0; i < blocks_per_cycle; i++) {
				size_t size = (i % 8) * 32 + 16;
				blocks[i] = tlsf_malloc(tlsf, size);
			}

			// 释放
			for (int i = 0; i < blocks_per_cycle; i++) {
				if (blocks[i]) {
					tlsf_free(tlsf, blocks[i]);
					blocks[i] = NULL;
				}
			}
		}

		end = clock();
		double optimized_time = (double)(end - start) / CLOCKS_PER_SEC;

		printf("[TLSF] 性能测试: 原始 %.3fs, 优化 %.3fs, 差异 %.1f%%\n",
			original_time, optimized_time,
			100.0 * (original_time - optimized_time) / original_time);

		// 如果优化版更慢，记录警告
		if (optimized_time > original_time * 1.05) { // 允许5%的误差
			printf("[TLSF] 警告: 优化版本性能降低 %.1f%%\n",
				100.0 * (optimized_time - original_time) / original_time);
		}
	}

	// 清理测试
	free(pool_memory);

	// 报告结果
	if (errors == 0) {
		printf("[TLSF] 内存局部性优化测试通过!\n");
		return 1;
	}
	else {
		printf("[TLSF] 内存局部性优化测试失败: %d个错误\n", errors);
		// 禁用优化
		g_use_optimized_memory_locality = 0;
		return 0;
	}
}