#!/bin/bash

if echo "$1" | grep -Eq '.*google\.\w{2,}\/amp\/s\/.*'; then
	UseGoogleAMPRegex='true'
fi
