# mac_nonet
Disable access to networking for ceraint group

To test, clone the repo and run `make && make load` in the module directory.

Set gid that shouldn't access the network: `sysctl security.mac.nonet.gid=31337` and enable enforcing:
`sysctl security.mac.nonet.enabled=1`.  Any call to `socket(2)` will end with `EPERM`.

You can also select group that can access only `AF_UNIX` sockets with `security.mac.nonet.local_gid`.
