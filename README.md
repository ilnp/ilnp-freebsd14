# UNDER CONSTRUCTION

# ILNP software prototype implementation in FreeBSD14
### ilnp-freebsd14
### 17 June 2024

## The first [ILNP](https://ilnp.cs.st-andrews.ac.uk/) software release for FreeBSD

This repository contains experimental software implementing a prototype of the Identifier Locator Network Protocol (ILNP). The main web site for ILNP is at [https://ilnp.cs.st-andrews.ac.uk/](https://ilnp.cs.st-andrews.ac.uk/).

The intention of this software release is to support the ognoing research and experimental results for the ILNP project.

The code here is an up-to-date version of the codebase used in the experiments documented in:

* G. T. Haywood, S. N. Bhatti, [Defence against side-channel attacks for encrypted network communication using multiple paths](https://doi.org/10.3390/cryptography8020022). Cryptography, vol. 8, no. 2, pages 1-26. May 2024.
* S. N. Bhatti, G. Haywood, R. Yanagida  [End-to-End Privacy for Identity & Location with IP](https://doi.org/10.1109/ICNP52444.2021.9651909). NIPAA21 - 2nd Workshop on New Internetworking Protocols, Architecture and Algorithms (ICNP 2021 - 29th IEEE International Conference on Network Protocols). Virtual event (COVID-19). Nov 2021.

This is the codebase that was also used for the experiments and demonstrations at the [IETF118/Prague Hackathon](https://blogs.cisco.com/developer/prague-ietf-hackathon), for which more information can be found [here](https://ilnp.cs.st-andrews.ac.uk/freebsd/20231105-ietf118_hackathon/).

## This is not supported software

Alas and woe, I cannot offer any support for this software. It is the output of ongoing work in various reserach projects (including PhD work) that I have supervised. Please be aware that you use this software at your own risk.

I continue to seek funding for progressing ILNP in various ways. So my intention is to improve and update this software, but I cannot give any definite timescales and roadmaps at present.

## Binary

A binary of the kernel and modified libc, calong wiht instructions on hot to use them with a fresh install of FreebSD14 can be found [here](xk).

## Source code

There are two parts to the source code:

1. Modifications to `libc` so that names for nodes in `/etc/hosts` can be mapped to ILNP Identifier-Locator Vector (I-LV) values, and passed up to applications in `struct addrinfo` via calls to `getaddrinfo(3)`.
2. Modifications and to the FreeBSD v14 kernel to implement the ILNP functionality.

Both are needed. First, get the tar.gz files package linked above. xk instructions xk

Source github repository: [https://github.com/ilnp/ilnp-freebsd14](https://github.com/ilnp/ilnp-freebsd14).

## Thank you

My thanks to you for your interest in [ILNP](https://ilnp.cs.st-andrews.ac.uk/)! I hope you enjoy trying it out.

_Saleem Bhatti, ILNP Project Lead_, ilnp-admin at st-andrews.ac.uk
