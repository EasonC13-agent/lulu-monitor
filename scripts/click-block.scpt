-- Click Block with proper settings (per endpoint + always)
tell application "System Events"
	tell process "LuLu"
		set alertWindow to first window whose name contains "Alert"
		
		-- Expand Details & Options if collapsed
		try
			set detailsBtn to button "Details & Options" of alertWindow
			click detailsBtn
			delay 0.3
		end try
		
		-- Find and set Rule Scope to "endpoint" (remote endpoint)
		try
			set scopePopup to first pop up button of alertWindow whose description contains "Scope"
			click scopePopup
			delay 0.2
			-- Select "endpoint" option
			click menu item "endpoint" of menu 1 of scopePopup
			delay 0.2
		on error
			-- Try by position if description doesn't work
			try
				set allPopups to every pop up button of alertWindow
				if (count of allPopups) ≥ 1 then
					set scopePopup to item 1 of allPopups
					click scopePopup
					delay 0.2
					click menu item "endpoint" of menu 1 of scopePopup
					delay 0.2
				end if
			end try
		end try
		
		-- Find and set Rule Duration to "always"
		try
			set durationPopup to first pop up button of alertWindow whose description contains "Duration"
			click durationPopup
			delay 0.2
			click menu item "always" of menu 1 of durationPopup
			delay 0.2
		on error
			-- Try by position if description doesn't work
			try
				set allPopups to every pop up button of alertWindow
				if (count of allPopups) ≥ 2 then
					set durationPopup to item 2 of allPopups
					click durationPopup
					delay 0.2
					click menu item "always" of menu 1 of durationPopup
					delay 0.2
				end if
			end try
		end try
		
		-- Click Block
		click button "Block" of alertWindow
	end tell
end tell
