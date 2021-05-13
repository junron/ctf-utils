# LIBC

This module supplements pwntools to assist in ret2libc attacks.

## `fetch_libc_ver` function
Usage: `fetch_libc_ver(addr: int, func="_IO_puts")`  
Returns a list of possible libc versions based on the address leaked from remote.  
Pass a second parameter if `puts` is not available.

## `download_libc` function
Usage: `download_libc(version, download_location)`  
Downloads libc binary to current directory, if it does not already exist.

## `set_libc_addr` function
Usage: `set_libc_addr(libc, puts_addr)`  
This function sets the libc offset of a binary given the leaked puts address.  
This function is an extreme convenience function, thus is not designed to be customizable.

## `system_shell` function
Usage: `set_libc_addr(libc)`  
Returns a tuple of (`system` address, `/bin/sh` address).  
Why does this function exist? `sys, sh = system_shell(libc)` is a lot cooler than
```python
sys = libc.symbols.system
sh = next(libc.search(b"/bin/sh"))
```
