tell application "System Events"
	tell process "LuLu"
		set alertWindow to first window whose name contains "Alert"
		click button "Allow" of alertWindow
	end tell
end tell