#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/([a-zA-Z0-9-]*\.)?(giphy\.com).*'; then
	echo "$1" | grep -Eq '.*(comment-cdn\.9gag\.com).*(\/comment-list.json\?).*' && Use9GAGRegex='false'
	[ "$UseGiphyRegex" != 'false' ] && UseGiphyRegex='true'
fi
