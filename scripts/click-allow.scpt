-- Click Allow with proper settings (per endpoint + always)
tell application "System Events"
	tell process "LuLu"
		set alertWindow to first window whose name contains "Alert"
		
		-- Set Rule Scope to "endpoint" via popup button
		try
			set scopePopup to pop up button 1 of alertWindow
			click scopePopup
			delay 0.2
			click menu item "endpoint" of menu 1 of scopePopup
			delay 0.2
		end try
		
		-- Set Rule Duration to "Always" via radio button
		try
			click radio button "Always" of alertWindow
			delay 0.1
		end try
		
		-- Click Allow
		click button "Allow" of alertWindow
	end tell
end tell
