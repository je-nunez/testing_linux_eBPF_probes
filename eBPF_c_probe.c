
// Avoid newer issue with CLang:
// https://github.com/iovisor/bcc/issues/2119

#ifdef asm_volatile_goto
#undef asm_volatile_goto
#define asm_volatile_goto(x...)
#endif

#include <linux/mmzone.h>

/*
 * This is an extended BPF kernel module, with some probes, for the IO Visor
 * BPF Compiler Collection (BCC) for an x86_64 architecture. (Tested on a
 * Linux kernel 4.3.3)
 *
 * You should not try to compile directly this code, for its compilation is
 * requested by the BCC. BCC also determines the point in the kernel to which
 * the probes in this module will attach, and instructs these attachments.
 *
 * In our case, the point is only called under one thread at a time, ie.,
 * there is no concurrent usage of the probe point, so the probe can't be
 * trigerred concurrently either.
 */

BPF_HISTOGRAM(delay_dist);

// These are scalar global variables, expressed in the form of a BPF array from
// indexes in [int] to values in 'u64', so these arrays have length = 1.

#define ENTRIES_SCALAR_VAR  1

BPF_TABLE("array", int, u64, global_var_time_at_entry, ENTRIES_SCALAR_VAR);

BPF_TABLE("array", int, u64, global_var_total_accum_nsec, ENTRIES_SCALAR_VAR);

// this is a hash having the accum delays in nanoseconds of the calls to
// "compact_zone(...)", and this hash is keyed by the "order" argument
// passed to this kernel function. (Very probably 128 different hash keys is
// way too a conservative allocation for this hash.)

#define HASH_BUCKETS_FOR_ORDERS   128

// (Note: we use the types here, "int", "unsigned long", "u64", mainly according
//  as we copy the types from the corresponding parameters in the probed kernel
//  functions, like in "kernel/mm/compaction.c", and, if the type is not taken
//  from the original kernel function, then the type is from the BPF auxiliary
//  functions; as last recourse, if no type can be inferred, is to give the type
//  ourselves.
//  To be clearer, we track the main type assumption with a typedef)

typedef unsigned int order_type;

BPF_TABLE("hash", order_type, u64, total_accum_nsec_per_order,
          HASH_BUCKETS_FOR_ORDERS);

// The saved "order" at entry in "compact_zone()"
BPF_TABLE("array", int, order_type, global_var_saved_order_at_entry,
          ENTRIES_SCALAR_VAR);

// The counter of how many different kmalloc() related operations happened
// specifically only while the memory compaction was running

BPF_TABLE("array", int, u64, global_var_cnt_kmalloc_order_trace,
          ENTRIES_SCALAR_VAR);

BPF_TABLE("array", int, u64, global_var_cnt___kmalloc,
          ENTRIES_SCALAR_VAR);

BPF_TABLE("array", int, u64, global_var_cnt___do_kmalloc_node,
          ENTRIES_SCALAR_VAR);

BPF_TABLE("array", int, u64, global_var_cnt_kmem_cache_alloc,
          ENTRIES_SCALAR_VAR);

BPF_TABLE("array", int, u64, global_var_cnt_kmem_cache_alloc_trace,
          ENTRIES_SCALAR_VAR);

BPF_TABLE("array", int, u64, global_var_cnt_malloc,
          ENTRIES_SCALAR_VAR);

BPF_TABLE("array", int, u64, global_var_cnt_kfree,
          ENTRIES_SCALAR_VAR);

BPF_TABLE("array", int, u64, global_var_cnt_kmem_cache_reap,
          ENTRIES_SCALAR_VAR);

BPF_TABLE("array", int, u64, global_var_cnt_kmem_cache_free,
          ENTRIES_SCALAR_VAR);

BPF_TABLE("array", int, u64, global_var_cnt_kmem_cache_destroy,
          ENTRIES_SCALAR_VAR);

BPF_TABLE("array", int, u64, global_var_cnt_kmem_cache_shrink,
          ENTRIES_SCALAR_VAR);

// Auxiliary functions to the BPF probes

static
u64 get_time_at_entry(void)
{
        u32 idx_zero = 0;
        u64 *ptr_time_at_entry = global_var_time_at_entry.lookup(&idx_zero);

        // the eBPF probe runs in kernel mode, so the kernel eBPF verifier is
        // very strict (for safety and stability), and will reject BPF
        // instructions with implicit assumptions, like that a pointer is not
        // null: you need to make explicit the veracity that a pointer is not
        // null, otherwise the kernel verifier will reject it.

        return (ptr_time_at_entry)? *ptr_time_at_entry: 0;
}

static
void set_time_at_entry(u64 new_value)
{
        u32 idx_zero = 0;
        u64 *ptr_time_at_entry = global_var_time_at_entry.lookup(&idx_zero);

        // same as comment above that the kernel verifier requires to check
        // explicitly for implicit assumptions
        if (ptr_time_at_entry)
                *ptr_time_at_entry = new_value;
}

static
u64 * get_total_accum_nsec(void)
{
        u32 idx_zero = 0;
        u64 *total_accum_t_ptr = global_var_total_accum_nsec.lookup(&idx_zero);

        return (total_accum_t_ptr)? total_accum_t_ptr: NULL;
}

static
u64 * get_total_accum_nsec_per_order(order_type order)
{
        u64 zero = 0;
        u64 *total_accum_t_ptr =
                total_accum_nsec_per_order.lookup_or_init(&order, &zero);

        return (total_accum_t_ptr)? total_accum_t_ptr: NULL;
}

static
order_type get_saved_order_at_entry(void)
{
        u32 idx_zero = 0;
        order_type *saved_order_ptr =
                global_var_saved_order_at_entry.lookup(&idx_zero);

        // same as comment above that the kernel verifier requires to check
        // explicitly for implicit assumptions

        return (saved_order_ptr)? *saved_order_ptr: 0;
}

static
void set_saved_order_at_entry(order_type new_value)
{
        u32 idx_zero = 0;
        order_type *saved_order_ptr =
                global_var_saved_order_at_entry.lookup(&idx_zero);

        // same as comment above that the kernel verifier requires to check
        // explicitly for implicit assumptions
        if (saved_order_ptr)
                *saved_order_ptr = new_value;
}

static
u64 * get_cnt_kmalloc_order_trace(void)
{
        u32 idx_zero = 0;
        u64 *cnt_ptr = global_var_cnt_kmalloc_order_trace.lookup(&idx_zero);

        return (cnt_ptr)? cnt_ptr: NULL;
}

static
u64 * get_cnt___kmalloc(void)
{
        u32 idx_zero = 0;
        u64 *cnt_ptr = global_var_cnt___kmalloc.lookup(&idx_zero);

        return (cnt_ptr)? cnt_ptr: NULL;
}

static
u64 * get_cnt___do_kmalloc_node(void)
{
        u32 idx_zero = 0;
        u64 *cnt_ptr = global_var_cnt___do_kmalloc_node.lookup(&idx_zero);

        return (cnt_ptr)? cnt_ptr: NULL;
}

static
u64 * get_cnt_kmem_cache_alloc(void)
{
        u32 idx_zero = 0;
        u64 *cnt_ptr = global_var_cnt_kmem_cache_alloc.lookup(&idx_zero);

        return (cnt_ptr)? cnt_ptr: NULL;
}

static
u64 * get_cnt_kmem_cache_alloc_trace(void)
{
        u32 idx_zero = 0;
        u64 *cnt_ptr = global_var_cnt_kmem_cache_alloc_trace.lookup(&idx_zero);

        return (cnt_ptr)? cnt_ptr: NULL;
}

static
u64 * get_cnt_malloc(void)
{
        u32 idx_zero = 0;
        u64 *cnt_ptr = global_var_cnt_malloc.lookup(&idx_zero);

        return (cnt_ptr)? cnt_ptr: NULL;
}

static
u64 * get_cnt_kfree(void)
{
        u32 idx_zero = 0;
        u64 *cnt_ptr = global_var_cnt_kfree.lookup(&idx_zero);

        return (cnt_ptr)? cnt_ptr: NULL;
}

static
u64 * get_cnt_kmem_cache_reap(void)
{
        u32 idx_zero = 0;
        u64 *cnt_ptr = global_var_cnt_kmem_cache_reap.lookup(&idx_zero);

        return (cnt_ptr)? cnt_ptr: NULL;
}

static
u64 * get_cnt_kmem_cache_free(void)
{
        u32 idx_zero = 0;
        u64 *cnt_ptr = global_var_cnt_kmem_cache_free.lookup(&idx_zero);

        return (cnt_ptr)? cnt_ptr: NULL;
}

static
u64 * get_cnt_kmem_cache_destroy(void)
{
        u32 idx_zero = 0;
        u64 *cnt_ptr = global_var_cnt_kmem_cache_destroy.lookup(&idx_zero);

        return (cnt_ptr)? cnt_ptr: NULL;
}

static
u64 * get_cnt_kmem_cache_shrink(void)
{
        u32 idx_zero = 0;
        u64 *cnt_ptr = global_var_cnt_kmem_cache_shrink.lookup(&idx_zero);

        return (cnt_ptr)? cnt_ptr: NULL;
}


// BPF probes

/*
 * Probed function:
 *
 * static unsigned long compact_zone(struct zone *zone, int order,
 *               gfp_t gfp_mask, enum migrate_mode mode, int *contended,
 *               int alloc_flags, int classzone_idx)
 *
 * (To understand the concepts around "zone", see:
 *      https://www.kernel.org/doc/gorman/html/understand/understand005.html
 *
 *  in "Understanding the Linux Virtual Memory Manager", at
 *  https://www.kernel.org/doc/gorman/
 * )
 */

int prb_eBPF_compact_zone_entry(struct pt_regs *ctx, struct zone *zone,
                                      int order)
{
        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // bpf_trace_printk() should only be called in a debug, non-prod
                // kernel
                // bpf_trace_printk("lost a return probe to clear time\\n");
                ;
        }

        // store the new time in the global variables array
        time_at_entry = bpf_ktime_get_ns();
        set_time_at_entry(time_at_entry);

        //     I'm confused on the following instruction to get an argument into
        //     the probed kernel function, I'm very sorry for this.
        //     The following instruction seems to be needed (?) if the parameter
        //     passing to the intercepted callee (compact_zone()) is through the
        //     CPU registers (e.g., through the SI register). I need to consult
        //     more (e.g., sections "3.2.3" and "A.2.1" of):
        //
        //           http://x86-64.org/documentation/abi.pdf
        //
        // order_type order = ctx->si;
        //
        //     If this instruction taking the "order" parameter from the SI
        //     register is correct, then the signature of this BPF function
        //     needs to be changed, as to remove the unnecessary "order"
        //     parameter in this BPF function.

        set_saved_order_at_entry(order);

        return 0;
}

int prb_eBPF_compact_zone_return(struct pt_regs *ctx)
{
        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry == 0) {
                // time_at_entry was not recorded at the entry point.
                // Skip this call and do nothing
                // bpf_trace_printk("lost an entry probe to set time\\n");
                // bpf_trace_printk() should only be called in a debug, non-prod
                // kernel
                ;
        } else {
                u64 delta = bpf_ktime_get_ns() - time_at_entry;
                delay_dist.increment(bpf_log2l(delta / 1000));

                // We use auxiliary get/set functions because this probe kernel
                // function is not called as intensively frequent as for the
                // calls to these getter/setters be too overwhelming in load

                u64 * total_accum_nsec = get_total_accum_nsec();
                if (total_accum_nsec)
                        (*total_accum_nsec) += delta;

                // update the accum time (in nanoseconds) to compact the memory
                // of this "order"

                unsigned int saved_order_at_entry = get_saved_order_at_entry();

                u64 * accum_nsec_order =
                        get_total_accum_nsec_per_order(saved_order_at_entry);
                if (accum_nsec_order)
                        (*accum_nsec_order) += delta;

                // clear the (saved) time in the global variables array
                set_time_at_entry(0);
        }

        return 0;
}


/*
 * Another probed kernel functions: kmalloc() family
 *
 * (Some of these functions are inlines so they can't be probed.)
 *
 * These BPF probes do not analyze the kmalloc()-types per-se, but the only the
 * ones that happen __while__ a compact_zone() is also happening. To see if a
 * compact_zone() is running in another thread, try to see if
 * get_time_at_entry() is set when a compact_zone() started
 */

int prb_eBPF_kmalloc_order_trace_return(struct pt_regs *ctx)
{

        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // it is set. Get a point to the counter and increment it.

                u64 * counter = get_cnt_kmalloc_order_trace();

                if (counter) (*counter) ++;
        }

        return 0;
}

int prb_eBPF___kmalloc_return(struct pt_regs *ctx)
{

        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // it is set. Get a point to the counter and increment it.

                u64 * counter = get_cnt___kmalloc();

                if (counter) (*counter) ++;
        }

        return 0;
}

int prb_eBPF___do_kmalloc_node_return(struct pt_regs *ctx)
{

        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // it is set. Get a point to the counter and increment it.

                u64 * counter = get_cnt___do_kmalloc_node();

                if (counter) (*counter) ++;
        }

        return 0;
}

int prb_eBPF_kmem_cache_alloc_return(struct pt_regs *ctx)
{

        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // it is set. Get a point to the counter and increment it.

                u64 * counter = get_cnt_kmem_cache_alloc();

                if (counter) (*counter) ++;
        }

        return 0;
}

int prb_eBPF_kmem_cache_alloc_trace_return(struct pt_regs *ctx)
{

        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // it is set. Get a point to the counter and increment it.

                u64 * counter = get_cnt_kmem_cache_alloc_trace();

                if (counter) (*counter) ++;
        }

        return 0;
}

int prb_eBPF_malloc_return(struct pt_regs *ctx)
{

        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // it is set. Get a point to the counter and increment it.

                u64 * counter = get_cnt_malloc();

                if (counter) (*counter) ++;
        }

        return 0;
}

int prb_eBPF_kfree_return(struct pt_regs *ctx)
{

        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // it is set. Get a point to the counter and increment it.

                u64 * counter = get_cnt_kfree();

                if (counter) (*counter) ++;
        }

        return 0;
}

int prb_eBPF_kmem_cache_reap_return(struct pt_regs *ctx)
{

        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // it is set. Get a point to the counter and increment it.

                u64 * counter = get_cnt_kmem_cache_reap();

                if (counter) (*counter) ++;
        }

        return 0;
}

int prb_eBPF_kmem_cache_free_return(struct pt_regs *ctx)
{

        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // it is set. Get a point to the counter and increment it.

                u64 * counter = get_cnt_kmem_cache_free();

                if (counter) (*counter) ++;
        }

        return 0;
}

int prb_eBPF_kmem_cache_destroy_return(struct pt_regs *ctx)
{

        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // it is set. Get a point to the counter and increment it.

                u64 * counter = get_cnt_kmem_cache_destroy();

                if (counter) (*counter) ++;
        }

        return 0;
}

int prb_eBPF_kmem_cache_shrink_return(struct pt_regs *ctx)
{

        u64 time_at_entry = get_time_at_entry();

        if (time_at_entry != 0) {
                // it is set. Get a point to the counter and increment it.

                u64 * counter = get_cnt_kmem_cache_shrink();

                if (counter) (*counter) ++;
        }

        return 0;
}

