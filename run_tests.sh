#!/bin/sh

export PYTHONPATH=$(pwd)

: ${VERSIONS:="python python3"}

for src in bimap.py bit.py buffer.py label.py dns.py
do
	echo "===" $src
	for py in $VERSIONS
	do
		echo "Testing:" $($py --version 2>&1)
		$py dnslib/$src
	done
done
