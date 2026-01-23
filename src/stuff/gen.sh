#!/bin/bash

xxd -i Pongo.bin > Pongo_bin.c
xxd -i sep_racer.bin > sep_racer_bin.c
xxd -i kpf.bin > kpf_bin.c
xxd -i overlay_iphoneos.bin > overlay_iphoneos_bin.c
xxd -i union_iphoneos.bin > union_iphoneos_bin.c
xxd -i overlay_tvos.bin > overlay_tvos_bin.c
xxd -i union_tvos.bin > union_tvos_bin.c
