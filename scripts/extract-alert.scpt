tell application "System Events"
	tell process "LuLu"
		set alertWindow to first window whose name contains "Alert"
		set allTexts to {}
		
		set allElements to entire contents of alertWindow
		repeat with elem in allElements
			try
				if class of elem is static text then
					set elemValue to value of elem
					if elemValue is not missing value and elemValue is not "" then
						set end of allTexts to elemValue
					end if
				end if
			end try
		end repeat
		
		set AppleScript's text item delimiters to "|||"
		return allTexts as text
	end tell
end tell