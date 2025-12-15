1. Open "Windows Event Viewer" on any Windows device
2. Use the `Open Saved Log` button and choose the given `evtx` file 
3. Filter out the events with the event code 4625 (failed login)
4. Manually scroll through the events to find a number of 4625 events has a login username of a Base64-encoded string, instead of a usual plaintext
5. Decode the string to get the name "Nova Laam" and the flag of this challenge