#!/bin/bash

# The network requests function. This will be used to get the direct link of shortened URLs
MakeNetworkRequest(){

	# If curl cannot access the link for any reason, the value of the "$URL" variable will be considered the "final URL"
	echo "$URL" > "$TrashURLFilename"
	# Make request
	timeout -s '9' "$ConnectionTimeout" curl -LNkZB --raw --head --ignore-content-length --no-progress-meter --no-sessionid --ssl-no-revoke --no-keepalive $NetworkProtocol $Socks5 --url "$URL" --user-agent "$UserAgent" $DoHOptions | grep -E '^(L|l)(O|o)(C|c)(A|a)(T|t)(I|i)(O|o)(N|n):\s*' | ParseText >> "$TrashURLFilename"
	# If the URL does not have a valid protocol, set it to http
	sed -ri 's/^(https?(:\/\/|%3A%2F%2F|%3a%2f%2f))?/http:\/\//g' "$TrashURLFilename"
	# Set received data
	URL=$(ParseText < "$TrashURLFilename" | tail -1)

}

# Delete placeholder files (from git), creat all needed directories and set all environment variables
SetupUnalix(){

	rm -f "$HOME/Unalix/Administrators/placeholder" "$HOME/Unalix/Reports/placeholder"
	[ -d "$HOME/Unalix/Rules" ] || { mkdir -p "$HOME/Unalix/Rules"; }
	[ -d "$HOME/Unalix/TempFiles" ] || { mkdir -p "$HOME/Unalix/TempFiles"; }
	[ -d "$HOME/Unalix/PatternDetection" ] || { mkdir -p "$HOME/Unalix/PatternDetection"; }
	[ -d "$HOME/Unalix/Administrators" ] || { mkdir -p "$HOME/Unalix/Administrators"; }
	[ -d "$HOME/Unalix/Reports" ] || { mkdir -p "$HOME/Unalix/Reports"; }
	
	# Import all variables from "$HOME/Unalix/Settings/Settings.txt"
	source "$HOME/Unalix/Settings/Settings.txt" || { echo -e '\033[0;31mAn error occurred while trying to import the settings file!'; exit; }

	# Check if "$BotToken" is a valid value
	[[ "$BotToken" =~ [0-9]+:[A-Za-z0-9_-]+ ]] || { echo -e '\033[0;31m"$BotToken" contains a invalid value. Unalix cannot be started!'; exit; }
	
	# Check if "$DoH" is a valid value'
	if [[ "$DoH" =~ https://[a-zA-Z0-9._-]{1,}\.[a-zA-Z0-9._-]{2,}(:443)?(/[a-zA-Z0-9._-]*)? ]]; then
		# If Tor traffic is enabled, disable DNS-over-HTTPS
		if [ "$TorTraffic" = 'true' ]; then
			unset 'DoHOptions' 
		else
			DoHOptions="--doh-url $DoH"
		fi
	fi
	
	# Check if "$TorTraffic" is set to "true"
	[ "$TorTraffic" = 'true' ] && Socks5='--socks5 127.0.0.1:9050' || { unset 'UseSocks5'; }

	# Check if "$DisableIPv4" is set to "true"
	[ "$DisableIPv4" = 'true' ] && NetworkProtocol='--ipv6' || { unset 'NetworkProtocol'; }
	
	# Check if "$DisableIPv6" is set to "true"
	[ "$DisableIPv6" = 'true' ] && NetworkProtocol='--ipv4' || { unset 'NetworkProtocol'; }

	# Check if "$ConnectionTimeout" is a valid value
	[[ "$ConnectionTimeout" =~ [0-9]+ ]] || { ConnectionTimeout='25'; }

	# Check if the package "idn" is installed
	if [[ "$(idn 'i❤️.ws')" != 'xn--i-7iq.ws' ]]; then
		echo -e '\033[0;31mThe "idn" package is not installed, inaccessible or has limitations!\033[0m'
	fi
	
	# Check if the package "idn2" is installed
	if [[ "$(idn2 'президент.рф')" != 'xn--d1abbgf6aiiy.xn--p1ai' ]]; then
		echo -e '\033[0;31mThe "idn2" package is not installed, inaccessible or has limitations!\033[0m'
	fi
	
	# Check if the package "bash" is installed
	if [[ -z "$(bash --version)" ]]; then
		echo -e '\033[0;31mThe "bash" package is not installed, inaccessible or has limitations!\033[0m'; exit '1'
	fi

	# Check if the package "curl" is installed
	if [[ -z "$(curl --version)" ]]; then
		echo -e '\033[0;31mThe "curl" package is not installed, inaccessible or has limitations!\033[0m'; exit '1'
	fi
	
	# Check if the package "jq" is installed
	if [[ -z "$(jq --version)" ]]; then
		echo -e '\033[0;31mThe "jq" package is not installed, inaccessible or has limitations!\033[0m'; exit '1'
	fi
	
	# Check if the package "vim" is installed
	if [[ -z "$(vim --version)" ]]; then
		echo -e '\033[0;31mThe "vim" package is not installed, inaccessible or has limitations!\033[0m'; exit '1'
	fi
	
	# Check if the package "xmlstarlet" is installed
	if [[ "$(echo '&amp;' | xmlstarlet -q 'unesc')" != '&' ]]; then
		echo -e '\033[0;31mThe "xmlstarlet" package is not installed, inaccessible or has limitations!\033[0m'; exit '1'
	fi
	
	# Set default permissions
	chmod -R '700' "$HOME/Unalix"
	
	return '0'

}

# Remove trackings parameters using regex patterns stored in the "$EndRegex" file
RemoveTrackingParameters(){

	# Parse "redirection" rules
	for RegexRules in $(grep -E '^Redirection\=' "$EndRegex" | sed -r '/^#.*|^$/d; s/^Redirection\=//g')
	do
		URL=$(echo "$URL" | sed -r "s/$RegexRules.*/\1/g")
	done

	# The "redirect" URL needs to be decoded, since it may contain encoded characters
	URL=$(URLDecode "$URL")

	# Remove specific fields
	for RegexRules in $(sed -r '/^Redirection\=/d; /^#.*|^$/d' < "$EndRegex")
	do
		URL=$(echo "$URL"| sed -r "s/\b$RegexRules//g")
	done

	# Parse "special" rules
	for SpecialRegexRules in $(sed -r '/^#.*|^$/d' < "$SpecialEndRegex")
	do
		URL=$(echo "$URL" | sed -r "$SpecialRegexRules")
	done

}

# This is used to decide which regex patterns will be (or not) used to remove tracking fields from links sent by users
DetectPatterns(){
	
	# Import all variables from scripts in "Unalix/PatternDetection"
	for Patterns in $(find "$HOME/Unalix/PatternDetection" -maxdepth '1' -type 'f' -regex '^.*PatternDetection\.sh$')
	do
		source "$Patterns" "$URL"
	done

	# Import all regex patterns that will be used
	[ "$UseMozawsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MozawsRules.txt" > "$EndRegex" && unset 'UseMozawsRegex'
	[ "$UseDoubleclickRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/DoubleclickRules.txt" >> "$EndRegex" && unset 'UseDoubleclickRegex'
	[ "$UseTechcrunchRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TechcrunchRules.txt" >> "$EndRegex" && unset 'UseTechcrunchRegex'
	[ "$UseFacebookRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/FacebookRules.txt" >> "$EndRegex" && unset 'UseFacebookRegex'
	[ "$UseNetflixRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/NetflixRules.txt" >> "$EndRegex" && unset 'UseNetflixRegex'
	[ "$UseCnetRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/CnetRules.txt" >> "$EndRegex" && unset 'UseCnetRegex'
	[ "$UseAliExpressRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/AliExpressRules.txt" >> "$EndRegex" && unset 'UseAliExpressRegex'
	[ "$UseCurseforgeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/CurseforgeRules.txt" >> "$EndRegex" && unset 'UseCurseforgeRegex'
	[ "$UseSpiegelRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/SpiegelRules.txt" >> "$EndRegex" && unset 'UseSpiegelRegex'
	[ "$UseYoukuRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/YoukuRules.txt" >> "$EndRegex" && unset 'UseYoukuRegex'
	[ "$UseTwitterRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TwitterRules.txt" >> "$EndRegex" && unset 'UseTwitterRegex'
	[ "$UsePrvnizpravyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/PrvnizpravyRules.txt" >> "$EndRegex" && unset 'UsePrvnizpravyRegex'
	[ "$UseBingRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/BingRules.txt" >> "$EndRegex" && unset 'UseBingRegex'
	[ "$UseEbayRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/EbayRules.txt" >> "$EndRegex" && unset 'UseEbayRegex'
	[ "$UseOzonRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/OzonRules.txt" >> "$EndRegex" && unset 'UseOzonRegex'
	[ "$UseLinkedInRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/LinkedInRules.txt" >> "$EndRegex" && unset 'UseLinkedInRegex'
	[ "$UseFacebookRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/FacebookRules.txt" >> "$EndRegex" && unset 'UseFacebookRegex'
	[ "$UseYouTubeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/YouTubeRules.txt" >> "$EndRegex" && unset 'UseYouTubeRegex'
	[ "$UseDailycodingproblemRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/DailycodingproblemRules.txt" >> "$EndRegex" && unset 'UseDailycodingproblemRegex'
	[ "$UseVivaldiRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/VivaldiRules.txt" >> "$EndRegex" && unset 'UseVivaldiRegex'
	[ "$UseReaddcRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/ReaddcRules.txt" >> "$EndRegex" && unset 'UseReaddcRegex'
	[ "$UseTchiboRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TchiboRules.txt" >> "$EndRegex" && unset 'UseTchiboRegex'
	[ "$UseVKRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/VKRules.txt" >> "$EndRegex" && unset 'UseVKRegex'
	[ "$UseSiteRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/Site.txt" >> "$EndRegex" && unset 'UseSiteRegex'
	[ "$UseWalmartRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/WalmartRules.txt" >> "$EndRegex" && unset 'UseWalmartRegex'
	[ "$UseNormlRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/NormlRules.txt" >> "$EndRegex" && unset 'UseNormlRegex'
	[ "$UseSteampoweredRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/SteampoweredRules.txt" >> "$EndRegex" && unset 'UseSteampoweredRegex'
	[ "$UseSite2Regex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/Site2Rules.txt" >> "$EndRegex" && unset 'UseSite2Regex'
	[ "$UseGoogleAdsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GoogleAdsRules.txt" >> "$EndRegex" && unset 'UseGoogleAdsRegex'
	[ "$UseWootRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/WootRules.txt" >> "$EndRegex" && unset 'UseWootRegex'
	[ "$Use9GAGRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/9GAGRules.txt" >> "$EndRegex" && unset 'Use9GAGRegex'
	[ "$UseImdbRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/ImdbRules.txt" >> "$EndRegex" && unset 'UseImdbRegex'
	[ "$UseMozawsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MozawsRules.txt" >> "$EndRegex" && unset 'UseMozawsRegex'
	[ "$UseGitHubRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GitHubRules.txt" >> "$EndRegex" && unset 'UseGitHubRegex'
	[ "$UseSteamcommunityRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/SteamcommunityRules.txt" >> "$EndRegex" && unset 'UseSteamcommunityRegex'
	[ "$UseShutterstockRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/ShutterstockRules.txt" >> "$EndRegex" && unset 'UseShutterstockRegex'
	[ "$UseNetParadeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/NetParadeRules.txt" >> "$EndRegex" && unset 'UseNetParadeRegex'
	[ "$UseGovdeliveryRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GovdeliveryRules.txt" >> "$EndRegex" && unset 'UseGovdeliveryRegex'
	[ "$UseMessengerRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MessengerRules.txt" >> "$EndRegex" && unset 'UseMessengerRegex'
	[ "$UseGoogleRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GoogleRules.txt" >> "$EndRegex" && unset 'UseGoogleRegex'
	[ "$UseSmartredirectRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/SmartredirectRules.txt" >> "$EndRegex" && unset 'UseSmartredirectRegex'
	[ "$UseVitamixRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/VitamixRules.txt" >> "$EndRegex" && unset 'UseVitamixRegex'
	[ "$UseIndeedRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/IndeedRules.txt" >> "$EndRegex" && unset 'UseIndeedRegex'
	[ "$UseMozillaZineRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MozillaZineRules.txt" >> "$EndRegex" && unset 'UseMozillaZineRegex'
	[ "$UseGiphyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GiphyRules.txt" >> "$EndRegex" && unset 'UseGiphyRegex'
	[ "$UseGenericRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GlobalRules.txt" >> "$EndRegex" && unset 'UseGenericRegex'
	[ "$UseTwitchRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TwitchRules.txt" >> "$EndRegex" && unset 'UseTwitchRegex'
	[ "$UseLinksynergyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/LinksynergyRules.txt" >> "$EndRegex" && unset 'UseLinksynergyRegex'
	[ "$UseAmazonRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/AmazonRules.txt" >> "$EndRegex" && unset 'UseAmazonRegex'
	[ "$UseTweakersRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TweakersRules.txt" >> "$EndRegex" && unset 'UseTweakersRegex'
	[ "$UseAmazonAdsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/AmazonAdsRules.txt" >> "$EndRegex" && unset 'UseAmazonAdsRegex'
	[ "$UseSite3Regex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/Site3Rules.txt" >> "$EndRegex" && unset 'UseSite3Regex'
	[ "$UseRedditRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/RedditRules.txt" >> "$EndRegex" && unset 'UseRedditRegex'
	[ "$UseDeviantartRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/DeviantartRules.txt" >> "$EndRegex" && unset 'UseDeviantartRegex'
	[ "$UseMozillaRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MozillaRules.txt" >> "$EndRegex" && unset 'UseMozillaRegex'
	[ "$UseDisqusRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/DisqusRules.txt" >> "$EndRegex" && unset 'UseDisqusRegex'
	[ "$UseHhdotruRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/HhdotruRules.txt" >> "$EndRegex" && unset 'UseHhdotruRegex'
	[ "$UseNytimesRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/NytimesRules.txt" >> "$EndRegex" && unset 'UseNytimesRegex'
	[ "$UseNypostRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/NypostRules.txt" >> "$EndRegex" && unset 'UseNypostRegex'
	[ "$UseGateRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/GateRules.txt" >> "$EndRegex" && unset 'UseGateRegex'
	[ "$UseTelefonicaVivoRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/TelefonicaVivoRules.txt" >> "$EndRegex" && unset 'UseTelefonicaVivoRegex'
	[ "$UseBloggerRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/BloggerRules.txt" >> "$EndRegex" && unset 'UseBloggerRegex'
	[ "$UseKabumRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/KabumRules.txt" >> "$EndRegex" && unset 'UseKabumRegex'
	[ "$UseOuoIoRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/OuoIoRules.txt" >> "$EndRegex" && unset 'UseOuoIoRegex'
	[ "$UseMercadoLibreRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Common/MercadoLibreRules.txt" >> "$EndRegex" && unset 'UseMercadoLibreRegex'
	[ "$UseGoogleAMPRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Special/GoogleAMPRules.txt" > "$SpecialEndRegex" && unset 'UseGoogleAMPRegex'
	[ "$UseMobileFieldsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Special/MobileFieldsRules.txt" >> "$SpecialEndRegex" && unset 'UseMobileFieldsRegex'

}

# Set filename variables
SetFilenameVariables(){

	rm -f "$OriginalLinksFilename" "$EndResults" "$CleanedURLs" "$SpecialEndRegex" "$EndRegex" "$TrashURLFilename" "$LinksFilename" "$GetFromURLsFilename"
	OriginalLinksFilename="$HOME/Unalix/TempFiles/OriginalLinks-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
	EndResults="$HOME/Unalix/TempFiles/EndResults-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
	CleanedURLs="$HOME/Unalix/TempFiles/CleanedURLs-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
	SpecialEndRegex="$HOME/Unalix/TempFiles/SpecialRegex-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
	EndRegex="$HOME/Unalix/TempFiles/EndRegex-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
	TrashURLFilename="$HOME/Unalix/TempFiles/TrashURL-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
	LinksFilename="$HOME/Unalix/TempFiles/Links-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
	GetFromURLsFilename="$HOME/Unalix/TempFiles/GetFromURLs-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"

}

# This is the main function. It calls all other functions related to removal of tracking fields
ParseTrackingParameters(){

	URL=$(URLDecode "$URL")

	DetectPatterns; RemoveTrackingParameters; SolveURLIssues

	MakeNetworkRequest

	URL=$(URLDecode "$URL")

	DetectPatterns; RemoveTrackingParameters; SolveURLIssues

}

# Get end results and check if it's valid
GetEndResults(){

	if [ "$BatchMode" != 'true' ]; then
		[[ "$URL" =~ ^https?://[a-zA-Z0-9._-]{1,}\.[a-zA-Z0-9._-]{2,}(:[0-9]{1,5})?(/|%2F|\?|#)?.*$ ]] && MakeURLCompatible && TypingStatus --stop-sending && sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "\`$URL\`" --parse_mode 'markdown' --disable_web_page_preview 'true' || { TypingStatus --stop-sending; sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "The \`ParseTrackingParameters\` function has returned an invalid result." --parse_mode 'markdown'; }; cleanup
	else
		[[ "$URL" =~ ^https?://[a-zA-Z0-9._-]{1,}\.[a-zA-Z0-9._-]{2,}(:[0-9]{1,5})?(/|%2F|\?|#)?.*$ ]] && MakeURLCompatible && URL=$(echo "$URL" | sed 's/\//\\\//g; s/&/\\&/g') && sed -ri "s/\s\(\*\)$/ > $URL/g" "$EndResults" || { sed -ri "s/\s\(\*\)$/ > Could not process this link/g" "$EndResults"; }
	fi

}

# Remove invalid code strokes and escape some characters to avoid errors when submitting the text to the Telegram API
MakeURLCompatible(){

	if [ "$BatchMode" != 'true' ]; then
		URL=$(echo "$URL" | sed -r 's/(%26|&){2,}//g; s/(\?&|%3f%26|%3F%26)/?/g; s/(%26|&)$//; s/(%3f|%3F|\?)$//; s/%26/&/g; s/(\s|%(25)?20)/ /g; s/%(25)?23/#/g; s/(%2F|\/)$//g') && SolveURLIssues --fix-wrong-decoding
		URL=$(URLEncode "$URL" | sed 's/%20/%2520/g') && SolveURLIssues --escape-character
	else
		URL=$(echo "$URL" | sed -r 's/&{2,}//g; s/\?&/?/g; s/(%26|&)$//; s/(%3F|\?)$//; s/(%2F|\/)$//g') && SolveURLIssues --fix-wrong-decoding
		URL=$(URLDecode "$URL" | sed -r 's/\s/%20/g') && SolveURLIssues --escape-character
	fi

}

# Delete files and and/or exit process
cleanup(){

	TypingStatus --stop-sending
	rm -f "$OriginalLinksFilename" "$EndResults" "$CleanedURLs" "$SpecialEndRegex" "$EndRegex" "$TrashURLFilename" "$LinksFilename" "$GetFromURLsFilename"
	exit '0'

}

# The "GenerateUserAgent" function is used to randomly generate valid user agents. Each request made via curl uses a different user agent.
# This is used to prevent websites accessed from tracing the access history and possibly blocking Unalix due to "suspicious traffic".

# Client versions are randomly generated, however operating system information is valid.
# Note that the purpose of this function is not to generate real user agents, but to generate user agents in valid format. That's enough to "trick" most websites.
# To make access even more "random" and secure, run Unalix over the Tor network and change your IP address (get a new identity) regularly (e.g: within 15 or 30 minutes).
GenerateUserAgent(){

	# http://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
	WindowsVersions=('4.10' 'NT 5.0' '4.90' 'NT 5.1' 'NT 5.2' 'NT 6.0' 'NT 6.1' 'NT 6.2' 'NT 6.3' 'NT 10.0')
	
	# http://macworld.co.uk/feature/mac/os-x-macos-versions-3662757/
	macOS_Versions=('10.6' '10.7' '10.8' '10.9' '10.10' '10.11' '10.12' '10.13' '10.14' '10.15')
	
	# http://en.wikipedia.org/wiki/Android_version_history
	AndroidVersions=('5.1.1' '6.0' '6.0.1' '7.0' '7.1.0' '7.1.2' '8.0' '8.1' '9.0' '10.0')
	
	# http://en.wikipedia.org/wiki/IOS_version_history
	iOSVersions=('4.2.1' '5.1.1' '6.1.6' '7.1.2' '9.3.5' '9.3.6' '10.3.3' '10.3.4' '12.4.4' '13.3')
	
	# System architectures
	SystemArchitectures=('32' '64')

	# Number = Browser
	# 0 = Firefox
	# 1 = Chrome
	# 2 = Opera
	# 3 = Vivaldi
	# 4 = Yandex
	
	# Number = Operating System
	# 0 = Windows
	# 1 = macOS
	# 2 = Linux
	# 3 = Android
	# 4 = iOS

	# Generate a random number between 0 and 4 (pick a browser)
	BrowserSelection=$(tr -dc '0-4' < '/dev/urandom' | head -c '1')

	# Generate a random user agent based on the number contained in the "$BrowserSelection" variable
	if [ "$BrowserSelection" = '0' ]; then
		GenerateFirefox
	elif [ "$BrowserSelection" = '1' ]; then
		GenerateChrome
	elif [ "$BrowserSelection" = '2' ]; then
		GenerateOpera
	elif [ "$BrowserSelection" = '3' ]; then
		GenerateVivaldi
	elif [ "$BrowserSelection" = '4' ]; then
		GenerateYandex
	else
		UserAgent='Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'
	fi

}

# Template: http://whatismybrowser.com/guides/the-latest-user-agent/chrome
GenerateChrome(){

	# Generate a random number between 0 and 4 (pick a operating system)
 	SystemSelection=$(tr -dc '0-4' < '/dev/urandom' | head -c '1')

	# Chrome on Windows
	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}; Win${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}; x${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Chrome on macOS
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Chrome on Linux
	elif [ "$SystemSelection" = '2' ]; then
		UserAgent="Mozilla/5.0 (X11; Linux x86_${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Chrome on Android
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Linux; Android ${AndroidVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]};) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Mobile Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Chrome on iOS
	elif [ "$SystemSelection" = '4' ]; then
		UserAgent="Mozilla/5.0 (iPhone; CPU iPhone OS ${iOSVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]} like Mac OS X) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) CriOS/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Mobile/$(tr -dc 'A-Z0-9' < '/dev/urandom' | head -c '7') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	else
		# If for some reason the "SystemSelection" variable returns an invalid value, set a predefined user agent (Chrome on Linux)
		UserAgent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36'
	fi

}

# Template: http://whatismybrowser.com/guides/the-latest-user-agent/firefox
GenerateFirefox(){

	# Generate a random number between 0 and 4 (pick a operating system)
	SystemSelection=$(tr -dc '0-4' < '/dev/urandom' | head -c '1')

	# Firefox on Windows
	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}; WOW${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}; rv:$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0) Gecko/$(tr -dc '0-9' < '/dev/urandom' | head -c '8') Firefox/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0"
	# Firefox on macOS
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}; rv:$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0) Gecko/$(tr -dc '0-9' < '/dev/urandom' | head -c '8') Firefox/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0"
	# Firefox on Linux
	elif [ "$SystemSelection" = '2' ]; then
		UserAgent="Mozilla/5.0 (X11; Linux i586; rv:$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0) Gecko/$(tr -dc '0-9' < '/dev/urandom' | head -c '8') Firefox/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0"
	# Firefox on Android
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Android ${AndroidVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}; Mobile; rv:$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0) Gecko/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0 Firefox/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0"
	# Firefox on iOS
	elif [ "$SystemSelection" = '4' ]; then
		UserAgent="Mozilla/5.0 (iPhone; CPU iPhone OS ${iOSVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]} like Mac OS X) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) FxiOS/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0 Mobile/$(tr -dc A-Z1-9 < '/dev/urandom' | head -c '5') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '2')"
	else
		# If for some reason the "SystemSelection" variable returns an invalid value, set a predefined user agent (Firefox on Linux)
		UserAgent='Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/71.0'
	fi

}

# Template: http://whatismybrowser.com/guides/the-latest-user-agent/opera
GenerateOpera(){

	# Generate a random number between 0 and 3 (pick a operating system)
	SystemSelection=$(tr -dc '0-3' < '/dev/urandom' | head -c '1')

	# Opera on Windows
	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}; Win${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}; x${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') OPR/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Opera on macOS
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') OPR/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Opera on Linux
	elif [ "$SystemSelection" = '2' ]; then
		UserAgent="Mozilla/5.0 (X11; Linux x86_${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') OPR/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Opera on Android
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Linux; Android ${AndroidVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}; AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Mobile Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') OPR/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	else
		# If for some reason the "SystemSelection" variable returns an invalid value, set a predefined user agent (Opera on Linux)
		UserAgent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36 OPR/65.0.3467.72'
	fi

}

# Template http://whatismybrowser.com/guides/the-latest-user-agent/vivaldi
GenerateVivaldi(){

	# Generate a random number between 0 and 3 (pick a operating system)
	SystemSelection=$(tr -dc '0-3' < '/dev/urandom' | head -c '1')

	# Vivaldi on Windows
	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}; WOW${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Vivaldi/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1')"
	# Vivaldi on macOS
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Vivaldi/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1')"
	# Vivaldi on Linux
	elif [ "$SystemSelection" = '2' ]; then
		UserAgent="Mozilla/5.0 (X11; Linux x86_${SystemArchitectures[$(tr -dc 0-1 < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Vivaldi/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1')"
	# Vivaldi on Android (This template was manually picked up by me from Vivaldi Beta for Android)
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Linux; Android ${AndroidVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Mobile Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') Vivaldi/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '4').$(tr -dc '0-9' < '/dev/urandom' | head -c '2')"
	else
		# If for some reason the "SystemSelection" variable returns an invalid value, set a predefined user agent (Vivaldi on Linux)
		UserAgent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36 Vivaldi/2.9'
	fi

}

# Template http://whatismybrowser.com/guides/the-latest-user-agent/yandex
GenerateYandex(){

	# Generate a random number between 0 to 1 and between 3 to 4 (pick a operating system)
	SystemSelection=$(tr -dc '0-13-4' < '/dev/urandom' | head -c '1')

	# Yandex on Windows
	if [ "$SystemSelection" = '0' ]; then
		UserAgent="Mozilla/5.0 (Windows ${WindowsVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') YaBrowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '3') Yowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Yandex on macOS
	elif [ "$SystemSelection" = '1' ]; then
		UserAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X ${macOS_Versions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]}) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') YaBrowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '1-9' < '/dev/urandom' | head -c '4') Yowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '1').$(tr -dc '0-9' < '/dev/urandom' | head -c '1') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Yandex on Android
	elif [ "$SystemSelection" = '3' ]; then
		UserAgent="Mozilla/5.0 (Linux; Android ${AndroidVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]};) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Chrome/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').0.$(tr -dc '1-9' < '/dev/urandom' | head -c '4').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') YaBrowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '1-9' < '/dev/urandom' | head -c '3') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	# Yandex on iOS
	elif [ "$SystemSelection" = '4' ]; then
		UserAgent="Mozilla/5.0 (iPhone; CPU iPhone OS ${iOSVersions[$(tr -dc '0-9' < '/dev/urandom' | head -c '1')]} like Mac OS X) AppleWebKit/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '1-9' < '/dev/urandom' | head -c '2') (KHTML, like Gecko) Version/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '0-9' < '/dev/urandom' | head -c '1') YaBrowser/$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '1-9' < '/dev/urandom' | head -c '2').$(tr -dc '0-9' < '/dev/urandom' | head -c '1').$(tr -dc '1-9' < '/dev/urandom' | head -c '3') Mobile/$(tr -dc A-Z1-9 < '/dev/urandom' | head -c '5') Safari/$(tr -dc '1-9' < '/dev/urandom' | head -c '3').$(tr -dc '1-9' < '/dev/urandom' | head -c '2')"
	else
		# If for some reason the "SystemSelection" variable returns an invalid value, set a predefined user agent (Yandex on macOS)
		UserAgent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 YaBrowser/19.6.0.1583 Yowser/2.5 Safari/537.36'
	fi

}

# Try to solve character parsing/decoding issues
SolveURLIssues(){

	if [ "$1" = '--fix-wrong-decoding' ]; then
		# Decide whether or not the "+" (plus sign) character should be considered a blank space
		if [[ "$URL" =~ .*\?.*\+.* ]]; then
			OriginalString=$(echo "$URL" | grep -Eo '\?.*[^?]' | sed 's/\//\\\//g')
			if [ "$BatchMode" != 'true' ]; then
				ModifiedString=$(echo "$OriginalString" | sed 's/+/ /g')
			else
				ModifiedString=$(echo "$OriginalString" | sed 's/+/%20/g')
			fi
			URL=${URL//$OriginalString/$ModifiedString}
		fi
	elif [ "$1" = '--escape-character' ]; then
		# Fix twitter search
		if [[ "$URL" =~ .*twitter\.com(/|%2(f|F))search(\?|%3(f|F))q(\=|%3(d|D)).* ]]; then
			if [ "$BatchMode" != 'true' ]; then
				URL=${URL//%23/%2523}
			else
				URL=${URL//#/%23}
			fi
		fi
	else
		# Fix twitter search
		if [[ "$URL" =~ .*twitter\.com/search\?q\=.* ]]; then
			URL=${URL//#/%23}
		fi
	fi

}

# Send a message with the text "Unalix is up" or "Unalix is down" when the bot is started (bash "$HOME/Unalix/StartUnalix.sh") or stopped (CTRL + C) from the terminal
SendBotStatus(){

	if [[ "$StatusChatID" =~ (-?[0-9]+|@?[A-Za-z0-9]{5,32}) ]]; then
		if [ "$1" = '--started' ]; then
			sendMessage --chat_id "$StatusChatID" --text 'Unalix is up.' 2>&1 1>&/dev/null || { echo '* An error occurred while trying to send the status!'; return '1'; }
		elif [ "$1" = '--stopped' ]; then
			sendMessage --chat_id "$StatusChatID" --text 'Unalix is down.' 2>&1 1>&/dev/null || { echo '* An error occurred while trying to send the status!'; return '1'; }
		else
			echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
		fi
	else
		echo -e '\033[0;31m"$StatusChatID" contains a invalid value!\033[0m'; return '1'
	fi

}

# This function is used to send the action "typing" to the chat of the user who sent a link. This status will be sent while Unalix is processing a link
TypingStatus(){

	# This is a loop. The action will be sent when the [-f "$MessageSent" ] command returns a positive value (0)
	if [ "$1" = '--start-sending' ]; then
		MessageSent="$HOME/Unalix/TempFiles/MessageSent-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt" && touch "$MessageSent"
		while [ -f "$MessageSent" ]
		do
			sendChatAction --chat_id "$message_chat_id" --action 'typing' 2>&1 1>&/dev/null
		done &
	# The loop will be broken when the $MessageSent file is deleted.
	elif [ "$1" = '--stop-sending' ]; then
		rm -f "$MessageSent"
	else
		echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
	fi

}

# The command "/report" allows users to send messages directly to the bot administrators. # This is useful for users who want to report bugs or give feedback.
# To prevent spam, users cannot submit new reports if a saved report already exists associated with their user ID
BotCommand_report(){

	# Send basic command usage information
	if [ "$1" = '--send-usage' ]; then
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/report <your_message_here>`\nor\n`!report <your_message_here>`\n\n*Example:*\n\n`/report This bot sucks! Why don'\''t you give up on him and commit suicide right away?`\nor\n`!report This bot sucks! Why don'\''t you give up on him and commit suicide right away?`\n\n*Description:*\n\nUse this command to send a direct message to bot administrators. If you prefer, enter your email or username so that we can contact you if necessary.' --parse_mode 'markdown' || { SendErrorMessage; }
	# Try to store the submitted report
	elif [ "$1" = '--store-user-report' ]; then
		if [ -f "$HOME/Unalix/Reports/$message_chat_id" ]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "You have previously submitted a report. Wait for it to be viewed by an administrator or delete it using \`/delete_report_$message_chat_id\` or \`!delete_report_$message_chat_id\`." --parse_mode 'markdown'
		else
			echo -e "$message_text" | sed -r 's/^(\!|\/)(R|r)(E|e)(P|p)(O|o)(R|r)(T|t)\s*//g' > "$HOME/Unalix/Reports/$message_chat_id" && sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "Your report has been submitted. If you want to delete your submitted report, send \`/delete_report_$message_chat_id\` or \`!delete_report_$message_chat_id\`." --parse_mode 'markdown' || { sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred when trying to submit your report.'; }
			for Administrators in $(cd "$HOME/Unalix/Administrators" && ls)
			do
				sendMessage --chat_id "$Administrators" --text "*An user has submitted the following report:*\n\n*User:*\n\n*Name:* \`$message_chat_first_name\`\n*Username:* \`$message_chat_username\`\n*Language:* \`$message_from_language_code\`\n*User ID:* \`$message_from_id\`\n*Message ID:* \`$message_message_id\`\n\n*Report:*\n\n\`$(cat "$HOME/Unalix/Reports/$message_chat_id" | head -c '3800')\`" --parse_mode 'markdown' || { sendMessage --chat_id "$BotAdministrators" --text "*An user has submitted the following report:*\n\n*User:*\n\n*Name:* \`$message_chat_first_name\`\n*Username:* \`$message_chat_username\`\n*Language:* \`$message_from_language_code\`\n*User ID:* \`$message_from_id\`\n*Message ID:* \`$message_message_id\`\n\n*Report:*\n\n\`The report was stored in "$HOME/Unalix/Reports/$message_chat_id")\`" --parse_mode 'markdown'; }
			done
		fi
	else
		echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
	fi

}

# The command "/cmd" is used to execute commands inside the terminal where Unalix is running
# Only administrators who have their user IDs saved in "$HOME/Unalix/Administrators" can use this command inside Telegram
BotCommand_cmd(){

	# Send basic command usage information
	if [ "$1" = '--send-usage' ]; then
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/cmd <command> <parameter>`\nor\n`!cmd <command> <parameter>`\n\n*Example:*\n\n`/cmd neofetch --stdout %26%26 echo "$?"`\nor\n`!cmd neofetch --stdout %26%26 echo "$?"`\n\n*Description:*\n\nThis command allows a user to execute bash commands inside the terminal on which Unalix is running. Only administrators are authorized to perform this operation.' --parse_mode 'markdown' || { SendErrorMessage; }
	# Try to run the command on terminal
	elif [ "$1" = '--run-on-terminal' ]; then
		if [ -f "$HOME/Unalix/Administrators/$message_chat_id" ]; then
			CommandOutput="$HOME/Unalix/TempFiles/Output-$(tr -dc '[:alnum:]' < '/dev/urandom' | head -c 10).txt"
			CommandToRun=$(echo "$message_text" | sed -r 's/^(\!|\/)(C|c)(M|m)(D|d)\s*//g; s/\\*//g; s/"\""/'\''/g')
			timeout -s '9' "$ConnectionTimeout" bash -c "$CommandToRun" 2>>"$CommandOutput" 1>>"$CommandOutput"; ExitStatus="$?"
			[[ $(wc -w < "$CommandOutput") != '0' ]] && sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "*OUTPUT (stdout and stderr):*\n\n\`$(cat $CommandOutput)\`" --parse_mode 'markdown' || { sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "The command was executed, but no standard output (stdout) or standard error (stderr) could be captured. The exit status code was \`$ExitStatus\`." --parse_mode 'markdown'; }; cleanup
		else
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'You are not an administrator of this bot, and therefore you are not authorized to execute commands through the terminal.' || { SendErrorMessage; }
		fi
	else
		echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
	fi

}

# The command "/delete_report" allows users to delete a report that was previously submitted.
# Bot administrators have privileges, so they can delete reports submitted by other users
BotCommand_del_report(){

	# Send basic command usage information
	if [ "$1" = '--send-usage' ]; then
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "*Usage:*\n\n\`/delete_report_<your_user_id>\`\nor\n\`!delete_report_<your_user_id>\`\n\n*Example:*\n\n\`/delete_report_$message_from_id\`\nor\n\`!delete_report_$message_from_id\`\n\n*Description:*\n\nThis command allows a user to delete a previously sent report. Common users cannot delete reports with an ID other than their own." --parse_mode 'markdown' || { SendErrorMessage; }
	# Try to delete the report
	elif [ "$1" = '--delete-user-report' ]; then
		DeletionRequestID=$(echo "$message_text" | sed -r 's/^(\!|/)(D|d)(E|e)(L|l)(E|e)(T|t)(E|e)_(R|r)(E|e)(P|p)(O|o)(R|r)(T|t)_//g')
		if [ "$DeletionRequestID" = "$message_from_id" ]; then
			if [ -f "$HOME/Unalix/Reports/$message_from_id" ]; then
				rm -f "$HOME/Unalix/Reports/$message_from_id" && sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Your report has been successfully deleted.' || { SendErrorMessage; }
			else
				sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'You have no saved reports.' || { SendErrorMessage; }
			fi
		elif [ -f "$HOME/Unalix/Administrators/$message_from_id" ]; then
			if [ -f "$HOME/Unalix/Reports/$DeletionRequestID" ]; then
				rm -f "$HOME/Unalix/Reports/$DeletionRequestID" && sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'This report has been successfully deleted.' || { SendErrorMessage; }
			else
				sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "There are no reports associated with this user ID (\`$DeletionRequestID\`)." --parse_mode 'markdown' || { SendErrorMessage; }
			fi
		else
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'You have attempted to delete a report that does not belong to your user ID. Only bot administrators can perform this action.' || { SendErrorMessage; }
		fi
	else
		echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
	fi

}

# Process links sent by users
ProcessLinks(){

	if [ "$GetFromURL" = 'true' ]; then
		echo -e "$message_text" | ParseText > "$GetFromURLsFilename"
		for Links in $(cat "$GetFromURLsFilename")
		do
			GetLinksContent | head -c '5242880' | ParseText >> "$LinksFilename"
		done
		rm -f "$GetFromURLsFilename" && unset 'GetFromURL'
	elif [ "$GetFromFile" = 'true' ]; then
		if [ "$message_document_file_size" -gt '20000000' ]; then
			unset 'GetFromFile'
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'This file exceeds the maximum limit of 20 MB. Try sending a smaller file.' || { SendErrorMessage; }; cleanup
		else
			DownloadFilePath=$(getFile --file_id "$message_document_file_id" | grep -Eo 'documents/.+')
			DownloadFile | ParseText > "$LinksFilename" || { SendErrorMessage; }
		fi
	else
		echo -e "$message_text" | ParseText > "$LinksFilename"
	fi

	if [[ $(wc -l < "$LinksFilename") -gt '1' ]]; then

		TypingStatus --start-sending && BatchMode='true'
		mv "$LinksFilename" "$OriginalLinksFilename" && rm -f "$LinksFilename" || { SendErrorMessage; }

		for Domain in $(GetDomainName < "$OriginalLinksFilename")
		do
			idn "$Domain" 2>&1 1>&/dev/null && Punycode=$(idn "$Domain")
			idn2 "$Domain" 2>&1 1>&/dev/null && Punycode=$(idn2 "$Domain")
			if [ "$Punycode" ]; then
				[ "$Punycode" != "$Domain" ] && sed -i "s/$Domain/$Punycode/g" "$OriginalLinksFilename"
				unset 'Punycode'
			fi
		done

		for URL in $(cat "$OriginalLinksFilename"); do
			echo "$URL (*)" >> "$EndResults"
			ParseTrackingParameters && GetEndResults
		done

		head -c '50000000' < "$EndResults" > "$CleanedURLs"
		TypingStatus --stop-sending && sendDocument --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --document "@$CleanedURLs" || { SendErrorMessage; }; cleanup

	else
		URL=$(cat "$LinksFilename" | ParseText | head -n '1')
		rm -f "$OriginalLinksFilename" "$LinksFilename"
			
		TypingStatus --start-sending
	
		Domain=$(echo "$URL" | GetDomainName)
		idn "$Domain" 2>&1 1>&/dev/null && Punycode=$(idn "$Domain")
		idn2 "$Domain" 2>&1 1>&/dev/null && Punycode=$(idn2 "$Domain")
	
		if [ "$Punycode" ]; then
			[ "$Punycode" != "$Domain" ] && URL="${URL//$Domain/$Punycode}"
			unset 'Punycode'
		fi
	
		ParseTrackingParameters && GetEndResults || { SendErrorMessage; }; cleanup

	fi

	cleanup

}

# This function is used to send an error message to the user when an operation returns a negative value.
SendErrorMessage(){

	TypingStatus --stop-sending; sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred while trying to process your request.'

}

# This function is used to download txt files
DownloadFile(){

	alias DownloadThis='timeout -s '9' "$ConnectionTimeout" curl -LNkZB --raw --no-progress-meter --no-sessionid --ssl-no-revoke --no-keepalive $NetworkProtocol $Socks5 --url "https://api.telegram.org:443/file/bot$BotToken/$DownloadFilePath" --user-agent "$UserAgent" $DoHOptions'
	eval DownloadThis

}

# This function is used to decode links sent by users (e.g: from "N%c3%a3o" to "Não").
# Code taken from https://gist.github.com/cdown/1163649
URLDecode(){

	printf '%b' "${*//%/\\x}"

}

# This function is used to encode links sent by users (e.g: from "Não" to "N%c3%a3o").
# Code taken from https://gist.github.com/cdown/1163649#gistcomment-1256298
URLEncode(){

	local BytesCount="${#1}"
	for (( i = 0; i < BytesCount; i++ )); do
		local URL="${1:i:1}"
		case "$URL" in
			[a-zA-Z0-9.~_-])
				printf "$URL";;
			*)
				printf "$URL" | xxd -p -c '1' | while read -r 'Result'; do printf "%%%s" "$Result"; done;;
		esac
	done

}


# This function is used to obtain the contents of the URLs sent using the command "/getfromurl"
GetLinksContent(){

	timeout -s '9' "$ConnectionTimeout" curl -LNkZB --raw --no-progress-meter --no-sessionid --ssl-no-revoke --no-keepalive $NetworkProtocol $Socks5 --url "$Links" --user-agent "$UserAgent" $DoHOptions

}

# This function is used to process the text of messages, txt files and web pages (obtain valid values).
ParseText(){

	xmlstarlet -q 'unesc' | sed -r 's/(\s|\t|"|\(|\)|<|>|,|'\'')+/\n/g; s/(H|h)(T|t)(T|t)(P|p)(S|s)?(:\/\/|%3A%2F%2F|%3a%2f%2f)/http\6/g' | grep -Eo "\bhttps?(://|%3A%2F%2F|%3a%2f%2f)[^\ $(printf '\n')$(printf '\t')\"(')<>,]+" | sed -r '/.{1,}\..{2,}(:[0-9]{1,5})?(\/|%2F|\?|#)?/!d' | awk 'NF && !seen[$0]++'

}

# This function is used to obtain the domain names of the links sent by users.
GetDomainName(){

	sed -r 's/^https?:\/\/|(\/|%2F|\?|#).*$//g' | tr '[:upper:]' '[:lower:]'

}

# This function is used to encode non-UTF-8 texts sent from the "/encodetext" command.
BotCommand_encodetext(){

	# Send basic command usage information
	if [ "$1" = '--send-usage' ]; then
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/encodetext <string_or_text_here>`\nor\n`!encodetext <string_or_text_here>`\n\n*Example:*\n\n`/encodetext %e7%be%a4%e9%9d%92%e3%81%ae%e3%83%a1%e3%82%b5%e3%82%a4%e3%82%a2`\nor\n`!encodetext %e7%be%a4%e9%9d%92%e3%81%ae%e3%83%a1%e3%82%b5%e3%82%a4%e3%82%a2`\n\n*Description:*\n\nThis command allows the user to convert non-UTF-8 characters to valid UTF-8 format.' --parse_mode 'markdown' || { SendErrorMessage; }; exit
	# Encode text
	elif [ "$1" = '--encode-text' ]; then
		DecodedText=$(echo -e "$message_text" | sed -r 's/^(\!|\/)(e|E)(n|N)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T)\s*//g' )
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "\`$(URLEncode "$DecodedText" | sed 's/%/%25/g' | head -c '4096')\`" --parse_mode 'markdown' || { SendErrorMessage; }; exit
	else
		echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
	fi
	
}

# This function is used to decode UTF-8 texts sent from the "/decodetext" command.
BotCommand_decodetext(){

	# Send basic command usage information
	if [ "$1" = '--send-usage' ]; then
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/decodetext <string_or_text_here>`\nor\n`!decodetext <string_or_text_here>`\n\n*Example:*\n\n`/decodetext %25c3%25a3%25c4%2581%25c3%25a5%25c3%25a4`\nor\n`!decodetext %25c3%25a3%25c4%2581%25c3%25a5%25c3%25a4`\n\n*Description:*\n\nThis command allows the user to convert UTF-8 characters to human-readable text.' --parse_mode 'markdown' || { SendErrorMessage; }; exit
	# Decode text
	elif [ "$1" = '--decode-text' ]; then
		sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "\`$(echo $message_text | sed -r 's/^(\!|\/)(d|D)(e|E)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T)\s*//g')\`" --parse_mode 'markdown' || { SendErrorMessage; }; exit
	else
		echo -e '\033[0;31mInvalid function call received!\033[0m'; return '1'
	fi

}

# Initial setup
SetupUnalix

# Generate (or not) a random user agent before each request
[ "$GenerateUserAgents" != 'false' ] && GenerateUserAgent || { UserAgent='Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/71.0'; }

# A basic internet connection check
echo -e '\033[0;33mChecking internet connection...\033[0m' && timeout -s '9' "$ConnectionTimeout" curl -s --raw --ignore-content-length --head --user-agent "$UserAgent" $NetworkProtocol $Socks5 --url 'https://www.gnu.org:443/robots.txt' $DoHOptions 1>/dev/null && echo -e '\033[0;32mSuccess!\033[0m' || { echo -e '\033[0;31mNo valid response received!\033[0m'; exit; }

# Check if the API can be accessed
echo -e '\033[0;33mChecking access to the API...\033[0m' && timeout -s '9' "$ConnectionTimeout" curl -s --raw --ignore-content-length --head --user-agent "$UserAgent" $NetworkProtocol $Socks5 --url 'https://api.telegram.org:443/robots.txt' $DoHOptions 1>/dev/null && echo -e '\033[0;32mSuccess!\033[0m' || { echo -e '\033[0;31mNo valid response received!\033[0m'; exit; }

# Import ShellBot functions library
echo -e '\033[0;33mImporting functions..\033[0m.' && source "$HOME/Unalix/Dependencies/ShellBot.sh" && echo -e '\033[0;32mSuccess!\033[0m' || { echo -e '\033[0;31mAn unknown error has occurred!\033[0m'; exit; }

# Start the bot
echo -e '\033[0;33mStarting bot...\033[0m' && init --token "$BotToken" 1>/dev/null; echo -e '\033[0;32mSuccess!\033[0m'

# Send "Unalix is up" to "$StatusChatID"
echo -e '\033[0;33mTrying to send bot status to the chat...\033[0m' && SendBotStatus --started && echo -e '\033[0;32mSuccess!\033[0m'

# Trap signals and other events
trap "echo -e '\033[0;33mTrying to send bot status to the chat...' && SendBotStatus --stopped && echo -e '\033[0;32mSuccess!\033[0m' ; cleanup" 'INT' 'TERM'

echo -e '\033[0;33mGetting updates from the API...\033[0m'

while true; do

	# Generate (or not) a random user agent before each request
	[ "$GenerateUserAgents" != 'false' ] && GenerateUserAgent || { UserAgent='Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/71.0'; }
	
	# Get updates from the API
	getUpdates --limit '1' --offset "$(OffsetNext)" --timeout "$ConnectionTimeout"

	# List received data
	for id in "$(ListUpdates)"; do

		# Check if the text sent is part of a file (e.g: photo, video or document)
		[ ! "$message_text" ] && message_text="$message_caption"

		if [[ "$message_text" =~ ^(\!|/)(S|s)(T|t)(A|a)(R|r)(T|t)$ ]]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Send via a message or inside a txt file the links you want to be "clean". Unalix will begin processing your request and within a few seconds (or minutes, depending on the number of links), it will send you the final result.\n\nUnalix is also able to process links from web pages. To do this, submit the URLs using the `/getfromurl` command. Unalix will download the entire contents of these URLs, obtain all the `http`/`https` links and process them in a batch operation.\n\nIn order to be able to identify the links contained in the message, txt file or web page, they must be in the following format:\n\n• It must start with `http://` or `https://` (case-insensitive)\n• It must have a domain name in Latin (`example.org`) or non-Latin (`президент.рф`) alphabet. Links with emoji domain name (`i❤️.ws`) are also supported.\n\n[Testing the bot with a link from an Amazon product](http://raw.githubusercontent.com/SnwMds/Unalix/master/Documentation/images/Example.png)\n\nIf you want Unalix to process multiple links from a single message, txt file or web page, separate them by a whitespace character (`\s`), tab (`\\t`), comma (`,`) or a new line (`\\n`).\n\n_Note: If you submit more than 1 link, the results will be sent in a txt file._\n\n[Testing the bot with multiple links in a single message](http://raw.githubusercontent.com/SnwMds/Unalix/master/Documentation/images/Example2.png)\n\nNote that Unalix can also identify links in forwarded messages and file captions.\n\nFor more information about Unalix, take a look at our [GitHub repository](http://github.com/SnwMds/Unalix) (Yes, it'\''s fully open source!).' --parse_mode 'markdown' --disable_web_page_preview 'true' || { SendErrorMessage; }; cleanup
		elif [[ "$message_text" =~ ^(\!|/)(R|r)(E|e)(P|p)(O|o)(R|r)(T|t)$ ]]; then
			BotCommand_report --send-usage
		elif [[ "$message_text" =~ ^(\!|/)(R|r)(E|e)(P|p)(O|o)(R|r)(T|t).+$ ]]; then
			BotCommand_report --store-user-report
		elif [[ "$message_text" =~ ^(\!|/)(C|c)(M|m)(D|d)$ ]]; then
			BotCommand_cmd --send-usage
		elif [[ "$message_text" =~ ^(\!|/)(C|c)(M|m)(D|d).+$ ]]; then
			BotCommand_cmd --run-on-terminal
		elif [[ "$message_text" =~ ^(\!|/)(D|d)(E|e)(L|l)(E|e)(T|t)(E|e)_(R|r)(E|e)(P|p)(O|o)(R|r)(T|t)$ ]]; then
			BotCommand_del_report --send-usage
		elif [[ "$message_text" =~ ^(\!|/)(D|d)(E|e)(L|l)(E|e)(T|t)(E|e)_(R|r)(E|e)(P|p)(O|o)(R|r)(T|t)_.{6,}$ ]]; then
			BotCommand_del_report --delete-user-report
		elif [[ "$message_text" =~ ^(\!|/)(e|E)(n|N)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T)$ ]]; then
			BotCommand_encodetext --send-usage
		elif [[ "$message_text" =~ ^(\!|/)(e|E)(n|N)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T).+$ ]]; then
			BotCommand_encodetext --encode-text
		elif [[ "$message_text" =~ ^(\!|/)(d|D)(e|E)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T)$ ]]; then
			BotCommand_decodetext --send-usage
		elif [[ "$message_text" =~ ^(\!|/)(d|D)(e|E)(c|C)(o|O)(d|D)(e|E)(t|T)(e|E)(x|X)(t|T).+$ ]]; then
			BotCommand_decodetext --decode-text
		elif [ "$message_document_mime_type" = 'text/plain' ]; then
			GetFromFile='true' && SetFilenameVariables && ProcessLinks
		elif [[ "$message_text" =~ ^(\!|/)(g|G)(e|E)(t|T)(f|F)(r|R)(o|O)(m|M)(u|U)(r|R)(l|L)$ ]]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/getfromurl <url_here>`\nor\n`!getfromurl <url_here>`\n\n*Example:*\n\n`/getfromurl http://example.org/links.txt,http://example.com/urls.html`\nor\n`!getfromurl http://example.org/links.txt,http://example.com/urls.html`\n\n*Description:*\n\nUnalix will obtain all http/https links contained in the URLs and process them in a batch operation.' --parse_mode 'markdown' || { SendErrorMessage; }; exit
		elif [[ "$message_text" =~ ^(\!|/)(g|G)(e|E)(t|T)(f|F)(r|R)(o|O)(m|M)(u|U)(r|R)(l|L).+$ ]]; then
			GetFromURL='true' && SetFilenameVariables && ProcessLinks
		elif [[ "$message_text" =~ .*(H|h)(T|t)(T|t)(P|p)(S|s)?(://|%3A%2F%2F|%3a%2f%2f)[^\ $(printf '\n')$(printf '\t')\"]* ]]; then
			SetFilenameVariables && ProcessLinks
		elif [ "$message_text" ]; then
			sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Send me any link that starts with `http://` or `https:// (case-insensitive)`.' --parse_mode 'markdown' || { SendErrorMessage; }; exit
		else
			exit '0'
		fi
	done & # Loops run in background
done

trap - 'INT' 'TERM'
