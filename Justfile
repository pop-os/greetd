rootdir := ''
etcdir := rootdir + '/etc'
prefix := rootdir + '/usr'
clean := '0'
debug := '0'
vendor := '0'
target := if debug == '1' { 'debug' } else { 'release' }
vendor_args := if vendor == '1' { '--frozen --offline' } else { '' }
debug_args := if debug == '1' { '' } else { '--release' }
cargo_args := vendor_args + ' ' + debug_args

bindir := prefix + '/bin'
systemddir := prefix + '/lib/systemd/system'

all: _extract_vendor
	cargo build {{cargo_args}}

# Installs files into the system
install:
	# main binaries
	install -Dm0755 target/release/greetd {{bindir}}/greetd
	install -Dm0755 target/release/agreety {{bindir}}/agreety

	# session config file
	install -Dm0644 config.toml {{rootdir}}/etc/greetd/config.toml
	
	# systemd service
	install -Dm0644 greetd.service {{systemddir}}/greetd.service

	# man files
	make -C man all install DESTDIR=../{{rootdir}} PREFIX=/usr

clean_vendor:
	rm -rf vendor vendor.tar .cargo/config

clean: clean_vendor
	cargo clean

# Extracts vendored dependencies if vendor=1
_extract_vendor:
	#!/usr/bin/env sh
	if test {{vendor}} = 1; then
		rm -rf vendor; tar pxf vendor.tar
	fi
