#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(steampowered\.com).*'; then
	UseSteampoweredRegex='true'
fi
