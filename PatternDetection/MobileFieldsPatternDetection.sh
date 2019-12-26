#!/bin/bash

if echo "$1" | grep -Eq '.*'; then
	[ "$UseMobileFieldsRegex" != 'false' ] && UseMobileFieldsRegex='true'
fi
