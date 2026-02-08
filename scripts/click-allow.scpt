-- Click Allow with proper settings (per endpoint + always)
tell application "System Events"
	tell process "LuLu"
		set alertWindow to first window whose name contains "Alert"
		
		-- Set Rule Scope to "remote endpoint" (index 1) via popup button
		-- Index 0 = Process, Index 1 = Remote Endpoint
		try
			set scopePopup to pop up button 1 of alertWindow
			click scopePopup
			delay 0.2
			-- Try different possible names
			try
				click menu item 2 of menu 1 of scopePopup
			on error
				try
					click menu item "remote endpoint" of menu 1 of scopePopup
				on error
					click menu item "endpoint" of menu 1 of scopePopup
				end try
			end try
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
