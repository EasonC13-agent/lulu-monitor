tell application "System Events"
	if exists process "LuLu" then
		tell process "LuLu"
			set alertWindows to (windows whose name contains "Alert")
			return (count of alertWindows) > 0
		end tell
	end if
	return false
end tell