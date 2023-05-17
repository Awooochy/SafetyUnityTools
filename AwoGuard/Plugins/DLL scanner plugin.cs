using System.Text;
using System.Diagnostics;
using System;
using UnityEngine;
using UnityEditor;
using System.IO;
using System.Collections.Generic;

public class DllScanner : AssetPostprocessor
{
    private static bool scannerEnabled = false;
    private static List<string> detectedDlls = new List<string>();

    private static readonly string suspiciousDllsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "/Suspicious dlls/";
    private static readonly string assetsFolder = Application.dataPath.Substring(0, Application.dataPath.Length - "Assets".Length);

    [MenuItem("Malicious Script Scanner/Enable DLL Scanner")]
    public static void EnableScanner()
    {
        scannerEnabled = true;
    }

    private void OnPreprocessAsset()
    {
        if (!scannerEnabled)
        {
            return;
        }

        // Check if the asset being imported is in the assets folder
        if (!assetImporter.assetPath.StartsWith("Assets/"))
        {
            return;
        }

        // Check if the asset being imported is a DLL
        if (assetImporter.importSettingsMissing || !assetImporter.assetPath.EndsWith(".dll"))
        {
            return;
        }

        // Get the path to the DLL file
        string dllPath = assetsFolder + assetImporter.assetPath;

        // Check if the DLL has already been detected as malicious
        if (detectedDlls.Contains(dllPath))
        {
            UnityEngine.Debug.LogWarning("Malicious DLL detected: " + assetImporter.assetPath);
            DisableDLL(assetImporter.assetPath);
            return;
        }

        // Check for malicious DLL contents
        byte[] dllBytes = File.ReadAllBytes(dllPath);
        if (dllBytes.Length > 0 && dllBytes[0] == 77 && dllBytes[1] == 90)
        {
            // Found a malicious DLL
            UnityEngine.Debug.LogWarning("Malicious DLL detected: " + assetImporter.assetPath);
            detectedDlls.Add(dllPath);
            MoveAndDisableDLL(dllPath, assetImporter.assetPath);
            EditorUtility.DisplayDialog("Malicious DLL Detected", "A malicious DLL was detected and has been moved to the \"Suspicious dlls\" folder on your desktop.", "OK");
        }
        else
        {
            // Check for hidden Discord webhooks encoded in Base64 strings
            string dllText = Encoding.ASCII.GetString(dllBytes);
            if (dllText.Contains("discordapp.com/api/webhooks/") && dllText.Contains("=="))
            {
                // Found a suspicious Base64 string that may contain a hidden Discord webhook
                UnityEngine.Debug.LogWarning("Suspicious Base64 string detected: " + assetImporter.assetPath);
                detectedDlls.Add(dllPath);
                MoveAndDisableDLL(dllPath, assetImporter.assetPath);
                EditorUtility.DisplayDialog("Suspicious Base64 String Detected", "A suspicious Base64 string that may contain a hidden Discord webhook was detected and has been moved to the \"Suspicious dlls\" folder on your desktop.", "OK");
            }
        }
    }
    private static void DisableDLL(string assetPath)
    {
        // Disable the DLL by moving it to a backup folder
        string backupFolder = Path.Combine(suspiciousDllsFolder, "Disabled DLLs");
        Directory.CreateDirectory(backupFolder);
        string backupPath = Path.Combine(backupFolder, Path.GetFileName(assetPath));
        File.Move(assetPath, backupPath);
    }

    private static void MoveAndDisableDLL(string dllPath, string assetPath)
    {
        // Move the DLL to the "Suspicious dlls" folder and disable it
        Directory.CreateDirectory(suspiciousDllsFolder);
        string newPath = Path.Combine(suspiciousDllsFolder, Path.GetFileName(dllPath));
        File.Move(dllPath, newPath);
        DisableDLL(assetPath);
    }

}
