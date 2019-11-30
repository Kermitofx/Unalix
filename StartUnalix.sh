#!/bin/bash

# The network requests function. This will be used to find the direct link of shortened URLs
MakeNetworkRequest(){
	# Make request
	wget -T '25' --no-dns-cache --no-cache --spider --no-proxy --no-check-certificate --no-hsts --user-agent 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0' "$URL" 2>&1 | grep -Eo '(http|https)://[^ \"]+' > "$CleanURLFilename"
	# Set received data
	URL=$(cat "$CleanURLFilename"| tail -1); SetFilenameVariables; echo "$URL" > "$TrashURLFilename"
}

# Creat all needed directories
SetupUnalix(){
	rm -f "$HOME/Unalix/Administrators/placeholder" "$HOME/Unalix/Reports/placeholder"
	[ -d "$HOME/Unalix/Rules" ] || { mkdir -p "$HOME/Unalix/Rules"; }
	[ -d "$HOME/Unalix/PatternDetection" ] || { mkdir -p "$HOME/Unalix/PatternDetection"; }
	[ -d "$HOME/Unalix/EndRegex" ] || { mkdir -p "$HOME/Unalix/EndRegex"; }
	[ -d "$HOME/Unalix/Results" ] || { mkdir -p "$HOME/Unalix/Results"; }
	[ -d "$HOME/Unalix/Outputs" ] || { mkdir -p "$HOME/Unalix/Outputs"; }
	[ -d "$HOME/Unalix/Administrators" ] || { mkdir -p "$HOME/Unalix/Administrators"; }
	[ -d "$HOME/Unalix/Reports" ] || { mkdir -p "$HOME/Unalix/Reports"; }
}

# Remove trackings parameters using regex patterns stored in the "$EndRegex" file
RemoveTrackingParameters(){
	# Parse "redirection" patterns
	cat "$EndRegex" | grep -E '^Redirection\=' | sed -r 's/^Redirection\=//g' | while read -r 'RegexRules'
	do
		sed -ri "s/$RegexRules/\1/g" "$TrashURLFilename"
	done

	# Remove specific parameters
	cat "$EndRegex" | sed -r '/^Redirection\=/d' | while read -r 'RegexRules'
	do
		sed -ri "s/$RegexRules//g" "$TrashURLFilename"
	done
	URL=$(cat "$TrashURLFilename"); rm -f "$EndRegex" "$TrashURLFilename"
}

DetectPatterns(){
	# Import all variables from scripts in "Unalix/PatternDetection"
	# This is used to decide which regex patterns will be (or not) used to remove tracking parameters of links sent by users
	source "$HOME/Unalix/PatternDetection/MozawsPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/DoubleclickPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/TechcrunchPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/FacebookPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GoogleAdsPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/NytimesPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/NetParadePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/VivaldiPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/YoukuPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/EbayPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GatePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GitHubPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/TchiboPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/MozillaZinePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/HhdotruPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/SteamcommunityPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/LinksynergyPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/SteampoweredPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/DailycodingproblemPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/TwitchPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GooglePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/PrvnizpravyPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/TwitterPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/DeviantartPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/YouTubePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/NypostPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GovdeliveryPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/SitePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/MozillaPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/Site3PatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GenericPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/IndeedPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/AmazonPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/VitamixPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/WootPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/DisqusPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/WalmartPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/AmazonAdsPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/ImdbPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/TweakersPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/MessengerPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/RedditPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/NormlPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/ReaddcPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/CnetPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/OzonPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/SpiegelPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/BingPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/GiphyPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/AliExpressPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/SmartredirectPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/LinkedInPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/9GAGPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/CurseforgePatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/VKPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/Site2PatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/NetflixPatternDetection.sh" "$URL"
	source "$HOME/Unalix/PatternDetection/ShutterstockPatternDetection.sh" "$URL"
	# Import all regex patterns that will be used
	[ "$UseMozawsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/MozawsRules.txt" > "$EndRegex" && unset 'UseMozawsRegex'
	[ "$UseDoubleclickRegex" = 'true' ] && cat "$HOME/Unalix/Rules/DoubleclickRules.txt" >> "$EndRegex" && unset 'UseDoubleclickRegex'
	[ "$UseTechcrunchRegex" = 'true' ] && cat "$HOME/Unalix/Rules/TechcrunchRules.txt" >> "$EndRegex" && unset 'UseTechcrunchRegex'
	[ "$UseFacebookRegex" = 'true' ] && cat "$HOME/Unalix/Rules/FacebookRules.txt" >> "$EndRegex" && unset 'UseFacebookRegex'
	[ "$UseNetflixRegex" = 'true' ] && cat "$HOME/Unalix/Rules/NetflixRules.txt" >> "$EndRegex" && unset 'UseNetflixRegex'
	[ "$UseCnetRegex" = 'true' ] && cat "$HOME/Unalix/Rules/CnetRules.txt" >> "$EndRegex" && unset 'UseCnetRegex'
	[ "$UseAliExpressRegex" = 'true' ] && cat "$HOME/Unalix/Rules/AliExpressRules.txt" >> "$EndRegex" && unset 'UseAliExpressRegex'
	[ "$UseCurseforgeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/CurseforgeRules.txt" >> "$EndRegex" && unset 'UseCurseforgeRegex'
	[ "$UseSpiegelRegex" = 'true' ] && cat "$HOME/Unalix/Rules/SpiegelRules.txt" >> "$EndRegex" && unset 'UseSpiegelRegex'
	[ "$UseYoukuRegex" = 'true' ] && cat "$HOME/Unalix/Rules/YoukuRules.txt" >> "$EndRegex" && unset 'UseYoukuRegex'
	[ "$UseTwitterRegex" = 'true' ] && cat "$HOME/Unalix/Rules/TwitterRules.txt" >> "$EndRegex" && unset 'UseTwitterRegex'
	[ "$UsePrvnizpravyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/PrvnizpravyRules.txt" >> "$EndRegex" && unset 'UsePrvnizpravyRegex'
	[ "$UseBingRegex" = 'true' ] && cat "$HOME/Unalix/Rules/BingRules.txt" >> "$EndRegex" && unset 'UseBingRegex'
	[ "$UseEbayRegex" = 'true' ] && cat "$HOME/Unalix/Rules/EbayRules.txt" >> "$EndRegex" && unset 'UseEbayRegex'
	[ "$UseOzonRegex" = 'true' ] && cat "$HOME/Unalix/Rules/OzonRules.txt" >> "$EndRegex" && unset 'UseOzonRegex'
	[ "$UseLinkedInRegex" = 'true' ] && cat "$HOME/Unalix/Rules/LinkedInRules.txt" >> "$EndRegex" && unset 'UseLinkedInRegex'
	[ "$UseFacebookRegex" = 'true' ] && cat "$HOME/Unalix/Rules/FacebookRules.txt" >> "$EndRegex" && unset 'UseFacebookRegex'
	[ "$UseYouTubeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/YouTubeRules.txt" >> "$EndRegex" && unset 'UseYouTubeRegex'
	[ "$UseDailycodingproblemRegex" = 'true' ] && cat "$HOME/Unalix/Rules/DailycodingproblemRules.txt" >> "$EndRegex" && unset 'UseDailycodingproblemRegex'
	[ "$UseVivaldiRegex" = 'true' ] && cat "$HOME/Unalix/Rules/VivaldiRules.txt" >> "$EndRegex" && unset 'UseVivaldiRegex'
	[ "$UseReaddcRegex" = 'true' ] && cat "$HOME/Unalix/Rules/ReaddcRules.txt" >> "$EndRegex" && unset 'UseReaddcRegex'
	[ "$UseTchiboRegex" = 'true' ] && cat "$HOME/Unalix/Rules/TchiboRules.txt" >> "$EndRegex" && unset 'UseTchiboRegex'
	[ "$UseVKRegex" = 'true' ] && cat "$HOME/Unalix/Rules/VKRules.txt" >> "$EndRegex" && unset 'UseVKRegex'
	[ "$UseSiteRegex" = 'true' ] && cat "$HOME/Unalix/Rules/Site.txt" >> "$EndRegex" && unset 'UseSiteRegex'
	[ "$UseWalmartRegex" = 'true' ] && cat "$HOME/Unalix/Rules/WalmartRules.txt" >> "$EndRegex" && unset 'UseWalmartRegex'
	[ "$UseNormlRegex" = 'true' ] && cat "$HOME/Unalix/Rules/NormlRules.txt" >> "$EndRegex" && unset 'UseNormlRegex'
	[ "$UseSteampoweredRegex" = 'true' ] && cat "$HOME/Unalix/Rules/SteampoweredRules.txt" >> "$EndRegex" && unset 'UseSteampoweredRegex'
	[ "$UseSite2Regex" = 'true' ] && cat "$HOME/Unalix/Rules/Site2Rules.txt" >> "$EndRegex" && unset 'UseSite2Regex'
	[ "$UseGoogleAdsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GoogleAdsRules.txt" >> "$EndRegex" && unset 'UseGoogleAdsRegex'
	[ "$UseWootRegex" = 'true' ] && cat "$HOME/Unalix/Rules/WootRules.txt" >> "$EndRegex" && unset 'UseWootRegex'
	[ "$Use9GAGRegex" = 'true' ] && cat "$HOME/Unalix/Rules/9GAGRules.txt" >> "$EndRegex" && unset 'Use9GAGRegex'
	[ "$UseImdbRegex" = 'true' ] && cat "$HOME/Unalix/Rules/ImdbRules.txt" >> "$EndRegex" && unset 'UseImdbRegex'
	[ "$UseMozawsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/MozawsRules.txt" >> "$EndRegex" && unset 'UseMozawsRegex'
	[ "$UseGitHubRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GitHubRules.txt" >> "$EndRegex" && unset 'UseGitHubRegex'
	[ "$UseSteamcommunityRegex" = 'true' ] && cat "$HOME/Unalix/Rules/SteamcommunityRules.txt" >> "$EndRegex" && unset 'UseSteamcommunityRegex'
	[ "$UseShutterstockRegex" = 'true' ] && cat "$HOME/Unalix/Rules/ShutterstockRules.txt" >> "$EndRegex" && unset 'UseShutterstockRegex'
	[ "$UseNetParadeRegex" = 'true' ] && cat "$HOME/Unalix/Rules/NetParadeRules.txt" >> "$EndRegex" && unset 'UseNetParadeRegex'
	[ "$UseGovdeliveryRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GovdeliveryRules.txt" >> "$EndRegex" && unset 'UseGovdeliveryRegex'
	[ "$UseMessengerRegex" = 'true' ] && cat "$HOME/Unalix/Rules/MessengerRules.txt" >> "$EndRegex" && unset 'UseMessengerRegex'
	[ "$UseGoogleRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GoogleRules.txt" >> "$EndRegex" && unset 'UseGoogleRegex'
	[ "$UseSmartredirectRegex" = 'true' ] && cat "$HOME/Unalix/Rules/SmartredirectRules.txt" >> "$EndRegex" && unset 'UseSmartredirectRegex'
	[ "$UseVitamixRegex" = 'true' ] && cat "$HOME/Unalix/Rules/VitamixRules.txt" >> "$EndRegex" && unset 'UseVitamixRegex'
	[ "$UseIndeedRegex" = 'true' ] && cat "$HOME/Unalix/Rules/IndeedRules.txt" >> "$EndRegex" && unset 'UseIndeedRegex'
	[ "$UseMozillaZineRegex" = 'true' ] && cat "$HOME/Unalix/Rules/MozillaZineRules.txt" >> "$EndRegex" && unset 'UseMozillaZineRegex'
	[ "$UseGiphyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GiphyRules.txt" >> "$EndRegex" && unset 'UseGiphyRegex'
	[ "$UseGenericRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GlobalRules.txt" >> "$EndRegex" && unset 'UseGenericRegex'
	[ "$UseTwitchRegex" = 'true' ] && cat "$HOME/Unalix/Rules/TwitchRules.txt" >> "$EndRegex" && unset 'UseTwitchRegex'
	[ "$UseLinksynergyRegex" = 'true' ] && cat "$HOME/Unalix/Rules/LinksynergyRules.txt" >> "$EndRegex" && unset 'UseLinksynergyRegex'
	[ "$UseAmazonRegex" = 'true' ] && cat "$HOME/Unalix/Rules/AmazonRules.txt" >> "$EndRegex" && unset 'UseAmazonRegex'
	[ "$UseTweakersRegex" = 'true' ] && cat "$HOME/Unalix/Rules/TweakersRules.txt" >> "$EndRegex" && unset 'UseTweakersRegex'
	[ "$UseAmazonAdsRegex" = 'true' ] && cat "$HOME/Unalix/Rules/AmazonAdsRules.txt" >> "$EndRegex" && unset 'UseAmazonAdsRegex'
	[ "$UseSite3Regex" = 'true' ] && cat "$HOME/Unalix/Rules/Site3Rules.txt" >> "$EndRegex" && unset 'UseSite3Regex'
	[ "$UseRedditRegex" = 'true' ] && cat "$HOME/Unalix/Rules/RedditRules.txt" >> "$EndRegex" && unset 'UseRedditRegex'
	[ "$UseDeviantartRegex" = 'true' ] && cat "$HOME/Unalix/Rules/DeviantartRules.txt" >> "$EndRegex" && unset 'UseDeviantartRegex'
	[ "$UseMozillaRegex" = 'true' ] && cat "$HOME/Unalix/Rules/MozillaRules.txt" >> "$EndRegex" && unset 'UseMozillaRegex'
	[ "$UseDisqusRegex" = 'true' ] && cat "$HOME/Unalix/Rules/DisqusRules.txt" >> "$EndRegex" && unset 'UseDisqusRegex'
	[ "$UseHhdotruRegex" = 'true' ] && cat "$HOME/Unalix/Rules/HhdotruRules.txt" >> "$EndRegex" && unset 'UseHhdotruRegex'
	[ "$UseNytimesRegex" = 'true' ] && cat "$HOME/Unalix/Rules/NytimesRules.txt" >> "$EndRegex" && unset 'UseNytimesRegex'
	[ "$UseNypostRegex" = 'true' ] && cat "$HOME/Unalix/Rules/NypostRules.txt" >> "$EndRegex" && unset 'UseNypostRegex'
	[ "$UseGateRegex" = 'true' ] && cat "$HOME/Unalix/Rules/GateRules.txt" >> "$EndRegex" && unset 'UseGateRegex'
}

# Set filename variables
SetFilenameVariables(){
	rm -f "$EndRegex" "$TrashURLFilename" "$CleanURLFilename"
	unset 'EndRegex' 'TrashURLFilename' 'CleanURLFilename'
	EndRegex="$HOME/Unalix/EndRegex/Regex-$(tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10).txt"
	TrashURLFilename="$HOME/Unalix/Results/TrashURL-$(tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10).txt"
	CleanURLFilename="$HOME/Unalix/Results/CleanURL-$(tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10).txt"
}

# This is the main function. It calls all other functions related to removal of tracking parameters
ParseTrackingParameters(){
	
	SetFilenameVariables
	
	echo "$URL" > "$TrashURLFilename"

	DetectPatterns; RemoveTrackingParameters
	
	MakeNetworkRequest

	DetectPatterns; RemoveTrackingParameters
	
	rm -f "$EndRegex" "$TrashURLFilename" "$CleanURLFilename"
	
}

# Get end results and check if it's valid
GetEndResults(){
	[[ "$URL" =~ ^(http|https):\/\/.+$ ]] && MakeURLCompatible && ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "\`$URL\`" --parse_mode 'markdown' || { ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "The \`ParseTrackingParameters\` function has returned an invalid result." --parse_mode 'markdown'; }
}

# Remove invalid code strokes and escape some characters to avoid errors when submitting the text to the Telegram API
MakeURLCompatible(){
	URL=$(echo "$URL" | sed -r 's/\&+//g; s/\&/\\&/g; s/\#/\\#/g; s/\[/\\[/g; s/\]/\\]/g; s/\(/\\(/g; s/\)/\\)/g; s/\?$//g')
}

# A basic internet connection check
echo '- Checking internet connection...' && wget --no-check-certificate --spider -T '10' 'https://www.gnu.org' 2>> '/dev/null' 1>> '/dev/null' && echo '- Success!' || { echo '* No response received!'; exit '1'; }

# Import ShellBot API
echo '- Importing functions...' && source "$HOME/Unalix/ShellBotCore/ShellBot.sh" && echo '- Success!' || { echo '* An unknown error has occurred!'; exit '1'; }

# Start the bot
echo '- Starting bot...' && SetupUnalix && ShellBot.init -m --token 'YOUR_API_KEY_HERE'

while :
do
	# Get updates from the API
	ShellBot.getUpdates --limit '100' --offset "$(ShellBot.OffsetNext)" --timeout '60'
	
	# List received data
	for id in "$(ShellBot.ListUpdates)"
	do
	# Thread
	(
		# Check if the message sent by the user is a valid link
		if [[ "$message_text" =~ ^(http|https):\/\/.+$ ]]; then
			URL="$message_text" && ParseTrackingParameters && GetEndResults

		# The command "report" allows users to send messages directly to the bot administrators.
		# This is useful for users who want to report bugs or give feedback
		# To prevent spam, users can only submit one report at a time
		elif [[ "$message_text" =~ ^(\!report|/report)$ ]]; then
			# Send  basic command usage information
			ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/report <your_message_here>` or `!report <your_message_here>`' --parse_mode 'markdown'
			# Check if the commands "/report" and "!report" are followed by one or more character
		elif [[ "$message_text" =~ ^(\!report|/report).+$ ]]; then
			# Check if there is already a saved report with the same user ID
			if [ -f "$HOME/Unalix/Reports/$message_chat_id" ]; then
				ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "You have previously submitted a report. Wait for it to be viewed by an administrator or delete it using \`/delete_report_${message_chat_id[$id]}\` or \`!delete_report_${message_chat_id[$id]}\`." --parse_mode 'markdown'
			else
				# Save the report at "$HOME/Unalix/Reports/$message_chat_id"
				echo "$message_text" | sed -r 's/^(\!report|\/report)\s*//g' > "$HOME/Unalix/Reports/$message_chat_id" && ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Your report has been submitted.' || { ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred when trying to submit your report.'; }
				# Tell all bot administrators that a user has submitted a new report
				cd "$HOME/Unalix/Administrators"; ls | while read -r 'BotAdministrators'
				do
					ShellBot.sendMessage --chat_id "$BotAdministrators" --text "*An user has submitted the following report:*\n\n*User:*\n\n*Name:* \`${message_chat_first_name}\`\n*Username:* \`${message_chat_username}\`\n*Language:* \`${message_from_language_code}\`\n*User ID:* \`$message_from_id\`\n*Message ID:* \`${message_message_id}\`\n\n*Report:*\n\n\`$(cat "$HOME/Unalix/Reports/$message_chat_id")\`" --parse_mode 'markdown' || { ShellBot.sendMessage --chat_id "$BotAdministrators" --text "*An user has submitted the following report:*\n\n*User:*\n\n*Name:* \`${message_chat_first_name}\`\n*Username:* \`${message_chat_username}\`\n*Language:* \`${message_from_language_code}\`\n*User ID:* \`$message_from_id\`\n*Message ID:* \`${message_message_id}\`\n\n*Report:*\n\n\`The report was stored in "$HOME/Unalix/Reports/$message_chat_id")\`" --parse_mode 'markdown'; }
				done
			fi

		# The command "cmd" is used to execute commands inside the terminal where Unalix is running
		# Only administrators who have their user IDs saved in "$HOME/Unalix/Administrators" can use this command inside Telegram
		elif [[ "$message_text" =~ ^(\!cmd|/cmd)$ ]]; then
			# Send  basic command usage information
			ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text '*Usage:*\n\n`/cmd <command>` or `!cmd <command>`' --parse_mode 'markdown'
		elif [[ "$message_text" =~ ^(\!cmd|/cmd).+$ ]]; then
			# Verify if the user is an administrator of the bot
			if [ -f "$HOME/Unalix/Administrators/$message_chat_id" ]; then
				# Set the filename for all command outputs
				CommandOutput="$HOME/Unalix/Outputs/Output-$(tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10).txt"
				
				# Remove the "!cmd" or "/cmd" strings 
				CommandToRun=$(echo "$message_text" | sed -r 's/^(\!cmd|\/cmd)\s*//g')
				
				# Run the command
				$CommandToRun 2>>"$CommandOutput" 1>>"$CommandOutput"
		
				# Send the output to the Telegram API
				[[ $(cat "$CommandOutput" | wc -w) != '0' ]] && ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "*OUTPUT (stdout and stderr):*\n\n\`$(cat $CommandOutput)\`" --parse_mode 'markdown' || { ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'The command was executed, but no standard output (stdout) could be captured.'; }
				
				# Remove the file with the output and unset variables
				rm -f "$CommandOutput"; unset 'CommandOutput' 'CommandToRun'
			else
				ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'You are not an administrator of this bot, so you are not authorized to execute this command.'
			fi

		# The command "delete_report" allows users to delete a report that was previously submitted.
		elif [[ "$message_text" =~ ^(/delete_report|\!delete_report)$ ]]; then
			# Send  basic command usage information
			ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text "*Usage:*\n\n\`/delete_report_$message_from_id\` or \`!delete_report_$message_from_id\`" --parse_mode 'markdown'
			# Check if the command "delete_report_" are followed by a user ID
		elif [[ "$message_text" =~ ^(/delete_report_|\!delete_report_).{6,}$ ]]; then
			# Remove the strings "/delete_report_" and "!delete_report_" from the variable
			DeletionRequest_ID=$(echo "$message_text" | sed -r 's/^(\/delete_report_|\!delete_report_)//g')
			# Check if the request ID and the the user ID are the same
			if [ "$DeletionRequest_ID" = "$message_from_id" ]; then
				# Check for any reports previously submitted by the user
				if [ -f "$HOME/Unalix/Reports/$message_from_id" ]; then
					# Delete the report submitted by the user and send the result to the Telegram API
					rm -f "$HOME/Unalix/Reports/$message_from_id" && ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Your report has been successfully deleted.' || { ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'An error occurred while trying to delete your report.'; }
				else
					ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'You have no saved reports.'
				fi
			else
				ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'You have attempted to delete a report that does not belong to your user ID. For security reasons, only administrators can perform this action.'
			fi
		else
			ShellBot.sendMessage --reply_to_message_id "$message_message_id" --chat_id "$message_chat_id" --text 'Send me any link that starts with `http://` or `https://`.' --parse_mode 'markdown' 2>/dev/null
		fi
	) &
	done
done
