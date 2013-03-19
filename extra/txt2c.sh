#!/bin/sh

txt2c() {
	sed \
		-e 's/\\/\\\\/g' \
		-e 's/"/\\\\"/g' \
		| while IFS= read line; do

		echo -n "\""
		echo -n "${line}"
		echo "\\\\n\""
	done
}

txt2c
