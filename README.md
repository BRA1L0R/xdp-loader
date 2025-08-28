# xdp-loader
[![Get binaries](https://img.shields.io/badge/Download_Binary-grey?logo=hackthebox&logoColor=white)](https://github.com/BRA1L0R/xdp-loader/releases)
[![GitHub Release](https://img.shields.io/github/v/release/BRA1L0R/xdp-loader?logo=rust)](https://github.com/BRA1L0R/xdp-loader)


### Key concepts and features
- Configuration file
  - Heavily inspired by **docker compose**, the base of every loadable project is a `Config.toml`
  - Pin location and jump tables can be configured through configuration files
  - You can load **many programs** on many **different interfaces** at once abd share maps and jump tables between them
- Folder structures
  - Maps and program sections will be saved in their corresponding folder with the same name as the section
  - Links will be saved with the following naming scheme: `{if name}_{program name}`
- Jump tables
  - A jump table is a `BPF_MAP_TYPE_PROG_ARRAY` that is filled with fds of neighbouring programs as
specified by configuration.
  - Each program can then reference other programs by calling `bpf_tail_call` with the correct index.



## Cli

```sh
Usage: xdp-loader [OPTIONS] <COMMAND>

Commands:
  attach
  detach
  help    Print this message or the help of the given subcommand(s)

Options:
  -p, --purge-maps       creates maps from scratch, scrapping previously pinned maps and their contents
  -v, --verbose          verbose debug output (Info)
      --vv               very verbose debug output (Debug)
  -s, --silent           limit console output to only hard errors
  -c, --config <CONFIG>  specifies a config file [default: ./Config.toml]
  -h, --help             Print help
```

Each command has options of its own. Run `xdp-loader <COMMAND> --help` to learn more.

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

> [!TIP]
> It is better to **NOT** pin a jump table to a folder.
>
> Pinning a jump table would create an ambiguos situation where one unloaded program could reference
> new loaded programs that have been put into the jump table instead of the original ones.

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



## Configuration

> [!CAUTION]
> Never change a configuration file's folders before detaching the
program, or else the loader won't know where to unload the programs / maps from.
This isn't dangerous as-is, but those resources could stay leaked forever!


> [!TIP]
> Remember to specify the `attach_mode` under `[[attach]]` to ensure maximum performance of your xdp program.
>
> Possible values for `attach_mode` are:
> - `skb`: emulated mode (default)
> - `driver`: driver mode, only available with supported NIC drivers
> - `hardware`: run BPF directly on supported NIC hardware

<details open>
<summary>Example configuration</summary>

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
attach_mode = "driver"
ifaces = ["eno1"]

# You can specify additional programs to load on different interfaces
#
# [[attach]]
# program = "xdp_entry_2"
# ifaces = ["eno2", "eno3"]

[[tables.JUMP_TABLE]]
program = "xdp_tcp_program"
index = 1

[[tables.JUMP_TABLE]]
program = "xdp_udp_program"
index = 2
```

</details>

This config file will fill the `JUMP_TABLE` program array in the following way:

| Index | Program |
|---|----|
| 0 | None |
| 1 | `xdp_tcp_program` |
| 2 | `xdp_udp_program` |

Ofcourse you're not required to setup a jump table if you don't need one.

<details open>
<summary>Minimal configuration example</summary>
  
```toml
[directories]
base = "/sys/fs/bpf/my_program"

[[attach]]
program = "xdp_entry"
ifaces = ["if1, if2, if3"]
```

</details>

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
