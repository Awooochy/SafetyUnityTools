using UnityEngine;
using UnityEditor;
using System.IO;
using System;

public class MaliciousScriptScanner : EditorWindow
{
    private bool scannerEnabled = false;

    [MenuItem("Malicious Script Scanner/Enable Scanner")]
    public static void EnableScanner()
    {
        MaliciousScriptScanner window = GetWindow<MaliciousScriptScanner>("Malicious Script Scanner");
        window.scannerEnabled = true;
    }

    private void OnGUI()
    {
        scannerEnabled = EditorGUILayout.Toggle("Enable Malicious Script Scanner", scannerEnabled);
    }

    private void Update()
    {
        if (!scannerEnabled)
        {
            return;
        }

        // Get the path to the project's Assets folder
        string projectPath = Application.dataPath;

        // Check for malicious scripts
        string[] allScriptPaths = AssetDatabase.GetAllAssetPaths();
        foreach (string scriptPath in allScriptPaths)
        {
            if (!scriptPath.EndsWith(".cs") || scriptPath.Contains("/DLL Scanner Plugin.cs") || scriptPath.Contains("/Webhook Killer Plugin.cs") || scriptPath == "/AwoGuard.cs")
            {
                continue;
            }
            if (!scriptPath.StartsWith(projectPath + "/Assets/"))
            {
                continue;
            }

            string scriptContents = File.ReadAllText(projectPath + "/" + scriptPath);

            if (scriptContents.Contains("AppData\\Roaming\\discord") ||
                scriptContents.Contains("AppData\\Local\\Google\\Chrome\\User Data"))
            {
                // Found a malicious script
                Debug.LogWarning("Malicious script detected: " + scriptPath);

                // Create the "Suspicious stuff" folder if it doesn't exist
                string suspiciousFolderPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "/Suspicious stuff";
                Directory.CreateDirectory(suspiciousFolderPath);

                // Move the detected script to the "Suspicious stuff" folder
                string detectedScriptPath = projectPath + "/" + scriptPath;
                string detectedScriptName = Path.GetFileName(scriptPath);
                string suspiciousScriptPath = suspiciousFolderPath + "/" + detectedScriptName;
                File.Copy(detectedScriptPath, suspiciousScriptPath);

                // Show a warning message to the user
                string warningMessage = "Malicious script detected: " + detectedScriptName + "\n" +
                    "Location: " + scriptPath + "\n" +
                    "Reason: Attempt to access sensitive data or perform malicious action";
                EditorUtility.DisplayDialog("Malicious Script Detected", warningMessage, "OK");
            }
        }
    }
}
