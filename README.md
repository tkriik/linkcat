# what

a link-level piping program, inspired by netcat

# usage

```
lc [-l] [-c channel] [-f source] [-t destination] <interface>
```

# options

| option	| default value	| description
| ----		| :----:	| ----
| -l		|		| accept data from local device address
| -c		| 0		| linkcat-specific virtual channel (0-65536)
| -f		| "any"		| source device address or "any"
| -t		| "any"		| destination device address or "any"

# build

run `make` and look in the `./bin/` folder

# tips

* use [Pipe Viewer](https://github.com/icetee/pv) to limit the rate of outbound data to prevent flooding the device, eg. `cat video.mpeg | pv -L 500K | lc -t any eth0`

# status

* probably compiles only on OpenBSD at the moment
* piping over Ethernet seems to work

# todo

* Linux support
* IEEE 802.11 support
* packet statistics
* better signal handling
