#!/bin/ksh

. ../testfunctions.sh

init "$@"

unload_kmod
load_kmod

# Run tests.
typeset rv=0

# Create DSRs and partial state.
(( rv && ! ErrIgnore )) || start_one_iptables_rule iptables PREROUTING 87.248.118.14 21 || rv=1
(( rv && ! ErrIgnore )) || start_one_loopback 87.248.118.12 1 || rv=1
(( rv && ! ErrIgnore )) || start_one_loopback 87.248.118.14 2 || rv=1

(( rv && ! ErrIgnore )) || start_one_iptables_rule ip6tables PREROUTING 2A00:1288:0080:800::5001 22 || rv=1
(( rv && ! ErrIgnore )) || start_one_loopback 2A00:1288:0080:800::5001 - || rv=1
(( rv && ! ErrIgnore )) || start_one_loopback 2A00:1288:0080:800::5003 - || rv=1

(( rv && ! ErrIgnore )) || docmd status ""    n:20  1 || rv=1

(( rv && ! ErrIgnore )) || docmd stop   ""    n:20  1 || rv=1

dsrcleanup

exit $rv
