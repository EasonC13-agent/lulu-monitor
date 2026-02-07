-- Click Block with Process lifetime (temporary rule)
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
		
		-- Set Rule Duration to "Process lifetime" via radio button
		try
			click radio button "Process lifetime" of alertWindow
			delay 0.1
		end try
		
		-- Click Block
		click button "Block" of alertWindow
	end tell
end tell
