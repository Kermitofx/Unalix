#!/bin/bash

if echo "$1" | grep -Eq '(.*google\.\w{2,}\/amp\/s\/.*|(\?|&)amp\b)'; then
	UseGoogleAMPRegex='true'
fi
