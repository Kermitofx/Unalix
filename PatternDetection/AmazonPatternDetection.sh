#!/bin/bash

if echo "$1" | grep -Eo '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(amazon)(\.[a-zA-Z]{2,}).*'; then
	echo "$1" | grep -Eo '.*(amazon\.).*(\/gp).*\/redirector.html\/.*' && UseAmazonRegex='false'
	echo "$1" | grep -Eo '.*(amazon\.).*(\/hz\/reviews-render\/ajax\/).*' && UseAmazonRegex='false'
	echo "$1" | grep -Eo '.*(amazon\.).*(\/gp).*\/cart\/ajax-update.html\/.*' && UseAmazonRegex='false'
	echo "$1" | grep -Eo '.*(amazon\.).*\/message-us\?.*' && UseAmazonRegex='false'
	[ "$UseAmazonRegex" != 'false' ] && UseAmazonRegex='true'
fi
