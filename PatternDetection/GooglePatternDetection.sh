#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(google)(\.[a-zA-Z]{2,}).*'; then
	echo "$1" | grep -Eq '.*(mail\.google\.).*(\/mail\/u\/0).*' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(google\.).*(\/upload)?(\/drive)\/.*' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(docs\.google\.).*\/.*' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(accounts\.google\.).*' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(google\.).*\/searchbyimage\?image_url=[^\/|\?|&]*(\/|&(amp;)?)?' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(hangouts\.google\.).*\/webchat.*zx=[^\/|\?|&]*(\/|&(amp;)?)?' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(client-channel\.google\.).*\/client-channel.*zx=[^\/|\?|&]*(\/|&(amp;)?)?' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(google\.).*\/complete\/search\?.*gs_[a-zA-Z]*=[^\/|\?|&]*(\/|&(amp;)?)?' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(google\.).*\/s\?tbm=map.*gs_[a-zA-Z]*=[^\/|\?|&]*(\/|&(amp;)?)?' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(news\.google\.).*\?hl=.*' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(google\.).*\/setprefs\?.*hl=[^\/|\?|&]*(\/|&(amp;)?)?' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(google\.).*\/appsactivity\/.*' && UseGoogleRegex='false'
	echo "$1" | grep -Eq '.*(google\.).*\/aclk\?.*' && UseGoogleRegex='false'
	[ "$UseGoogleRegex" != 'false' ] && UseGoogleRegex='true'
fi
