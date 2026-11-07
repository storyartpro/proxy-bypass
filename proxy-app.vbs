' Proxy Bypass: silent launcher (no console window).
' Resolves node.exe explicitly and starts the app from the app subfolder.

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

base = fso.GetParentFolderName(WScript.ScriptFullName)
node = "node"
If fso.FileExists("C:\Program Files\nodejs\node.exe") Then
  node = "C:\Program Files\nodejs\node.exe"
End If

shell.Environment("PROCESS")("PROXY_APP_DATA") = base & "\data"
shell.Environment("PROCESS")("PROXY_APP_PORT") = "8077"
shell.CurrentDirectory = base & "\app"
shell.Run """" & node & """ server.mjs", 0, False
