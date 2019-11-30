#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(facebook)(\.[a-zA-Z]{2,}).*'; then
	echo "$1" | grep -Eq '.*(facebook\.)\w{2,}.*(\/plugins\/).*' && UseFacebookRegex='false'
	echo "$1" | grep -Eq '.*(facebook\.)\w{2,}.*(\/dialog\/share).*' && UseFacebookRegex='false'
	echo "$1" | grep -Eq '.*(facebook\.)\w{2,}.*(\/groups\/member_bio\/bio_dialog\/).*' && UseFacebookRegex='false'
	echo "$1" | grep -Eq '.*(facebook\.)\w{2,}.*(\/photo\.php\?).*' && UseFacebookRegex='false'
	echo "$1" | grep -Eq '.*(facebook\.)\w{2,}.*(\/ajax\/).*' && UseFacebookRegex='false'
	[ "$UseFacebookRegex" != 'false' ] && UseFacebookRegex='true'
fi
