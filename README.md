# bsppatch

This is a **work-in-progress** offline BSP patcher targetting C99. It attempts to follow the [BSP specification](docs/SPECS.md).

## The heck is a BSP?

[BSP](https://github.com/aaaaaa123456789/bsp) is ax6's rather unique patch format. TL;DR: It's like multiple IPS files in a trench coat, and given Turing completeness. It's a programmable, "smart" patch, rather than only a single set of changes. Some things you can do with BSP include:
* Have ten different versions of your mod in a single file that the user will then choose.
* Able to support multiple revisions of the base game and conditionally use the right patch.
* Upgrading save files.

This should **not** be confused with [BPS](https://github.com/blakesmith/rombp/blob/master/docs/bps_spec.md), which is an improved patching format but does not offer programmability.

## How do I build this?

```sh
mkdir build && cd build
cmake ..
make
```

## It doesn't work!

Yet. But hey, the Prism patch easter egg works, at least.

There's still like a hundred opcodes left to implement, so…