## Details

### Key concepts
- Folder structures
  - Maps and program sections will be saved in their corresponding folder with the same name as the section
  - Links will be saved with the following naming scheme: `{if name}_{program name}`
- Jump tables:
  - A jump table is a `BPF_MAP_TYPE_PROG_ARRAY` that is filled with fds of neighbouring programs as
specified by configuration.
  - Each program can then reference other programs by calling `bpf_tail_call` with the correct index.

### TODO

- [x] Do not reuse jump table maps (fixes race condition where an old program could possibly jump to a new program)
- [ ] Reuse existing links (0 downtime replacement)


## Cli

Attaching a program
```sh
xdp-loader attach bpf_file.o
```

You can explore all program functionalities through the `help` command (powered by [clap](docs.rs/clap))

## Writing programs
### Section and section names

XDP programs export names under sections specified by the `SEC(...)` directive.

What `xdp-loader` is interested in is the **name of the function** exported by
the compiled program, not the name of the section it is exported in.

| Object | Section | Directive |
|---|---|---|
| Programs | xdp | `SEC("xdp")` |
| Map | .maps | `SEC(".maps")` |

### Map pinning

This loader uses the LIBBPF pinning convention for map pinning. To have a map pinned by the aforementioned convention you must specify the `LIBBPF_PIN_BY_MAME` flag.

Example map definition:
```c
struct
{
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __uint(max_entries, 1000);
   __type(key, __u32);
   __type(value, __u32);
   __uint(pinning, LIBBPF_PIN_BY_NAME);
} my_pinned_map SEC(".maps");
```

> [!WARNING]
> It is better to **NOT** pin a jump table to a folder.
>
> Pinning a jump table would create an ambiguos situation where one unloaded program could reference
> new loaded programs that have been put into the jump table instead of the original ones.


## Example
### Configuration

> [!CAUTION]
> Never change a configuration file's folders before detaching the
program, or else the loader won't know where to unload the programs / maps from.
This isn't dangerous as-is, but those resources could stay leaked forever!

Example configuration
```toml
[directories]
base = "/sys/fs/bpf/my_program"

[directories.overrides]
#
# You can specify overrides for the folders if your existing tooling needs it
#
# maps = "{base}/maps"
# programs = "{base}/programs"
# links = "{base}/links"

[[attach]]
program = "xdp_entry"
ifaces = ["eno1"]

[[tables.JUMP_TABLE]]
program = "xdp_tcp_program"
index = 1

[[tables.JUMP_TABLE]]
program = "xdp_udp_program""
index = 2
```

This config file will fill the `JUMP_TABLE` program array in the following way:

| Index | Program |
|---|----|
| 0 | None |
| 1 | `xdp_tcp_program` |
| 2 | `xdp_udp_program` |

Ofcourse you're not obligated to setup a jump table if you don't require it
```toml
[directories]
base = "/sys/fs/bpf/my_program"

maps = "/sys/fs/bpf/maps"
programs = ""
links = "/sys/fs/bpf/links"

[[attach]]
program = "section_name"
ifaces = ["if1, if2, if3"]
```

### Example Program

```c
// imports are excluded for the sake of brevity

struct
{
   __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
   __uint(max_entries, 1000);
   __type(key, __u32);
   __type(value, __u32);
} JUMP_TABLE SEC(".maps");

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u64 eth_off = sizeof(*eth);
    struct iphdr *iph = data + eth_off;

    // standard bound checking formalities
    if (eth + 1 > data_end)
        return XDP_DROP;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    if (iph + 1 > data_end)
        return XDP_DROP;

    if (iph->protocol == IPPROTO_TCP)
        bpf_tail_call(ctx, &JUMP_TABLE, 1);
    else if (iph->protocol == IPPROTO_UDP)
        bpf_tail_call(ctx, &JUMP_TABLE, 2);

   return XDP_PASS;
}

SEC("xdp")
int xdp_tcp_program(struct xdp_md *ctx) {
    return XDP_DROP;
}

SEC("xdp")
int xdp_udp_program(struct xdp_md *ctx) {
    return XDP_DROP;
}
```
