#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/([a-zA-Z0-9-]*\.)?(site2\.com).*'; then
	UseSite2Regex='true'
fi
