#!/bin/bash

if echo "$1" | grep -Eq '(https:\/\/|http:\/\/)([a-zA-Z0-9-]*\.)?(youku\.com).*'; then
	UseYoukuRegex='true'
fi
