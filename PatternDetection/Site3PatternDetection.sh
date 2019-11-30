#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/([a-zA-Z0-9-]*\.)?(site3\.com).*'; then
	UseSite3Regex='true'
fi
