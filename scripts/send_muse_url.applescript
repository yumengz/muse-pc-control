on run arguments
    if (count of arguments) is not 2 then error "Expected recipient and HTTPS URL"

    set recipientAddress to item 1 of arguments
    set museURL to item 2 of arguments
    if museURL does not start with "https://" then error "Refusing to send a non-HTTPS URL"

    set messageText to "Muse PC Control is ready: " & museURL & return & return & "Use the bearer token from your password manager. The token is intentionally not included in this message."

    tell application "Messages"
        set iMessageService to first service whose service type = iMessage
        set recipientBuddy to buddy recipientAddress of iMessageService
        send messageText to recipientBuddy
    end tell
end run
