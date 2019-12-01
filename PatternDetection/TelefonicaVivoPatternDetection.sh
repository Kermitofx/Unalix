#!/bin/bash

if echo "$1" | grep -Eq 'https?:\/\/(.+)?(\.vivo\.com\.br).*'; then
	[ "$UseTelefonicaVivoRegex" != 'false' ] && UseTelefonicaVivoRegex='true'
fi