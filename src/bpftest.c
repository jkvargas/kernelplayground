#include "vmlinux.h"
#include <bpf/bpf.h>
#include <bpf/bpf_helpers.h>

// typedef struct {
//   __u32 type;
//   __u32 key_size;
//   __u32 value_size;
//   __u32 max_entries;
//   __u32 map_flags;
// } bpf_map_def;

// bpf_map_def SEC(".maps") some_map = {
//   .key_size = sizeof(__u32),
//   .value_size = sizeof(__u64),
//   .type = BPF_MAP_TYPE_HASH,
//   .max_entries = 42,
//   .map_flags = 0,
// };

char LICENSE[] SEC("license") = "Dual BSD/GPL";

__s32 my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
  __s32 handle_tp(void *ctx) {
  __s32 pid = bpf_get_current_pid_tgid() >> 32;

  if (pid == my_pid) {
    return 0;
  }

  bpf_printk("BPF triggered from PID $d.\n", pid);

  return 0;
}
