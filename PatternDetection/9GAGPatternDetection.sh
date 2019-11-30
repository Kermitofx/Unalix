#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/([a-zA-Z0-9-]*\.)?(9gag\.com).*'; then
	echo "$1" | grep -Eq '.*(comment-cdn\.9gag\.com).*(\/comment-list.json\?).*' && Use9GAGRegex='false'
	[ "$Use9GAGRegex" != 'false' ] && Use9GAGRegex='true'
fi
