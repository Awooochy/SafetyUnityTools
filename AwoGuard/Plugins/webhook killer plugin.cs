using UnityEngine;
using UnityEditor;
using System.IO;
using System.Linq;

public class WebhookScanner : EditorWindow
{
    private bool webhookScannerEnabled = false;

    [MenuItem("Window/Webhook Scanner")]
    public static void ShowWindow()
    {
        EditorWindow.GetWindow(typeof(WebhookScanner));
    }

    [MenuItem("Malicious Script Scanner/Enable Webhook Scanner")]
    public static void EnableScanner()
    {
        WebhookScanner window = (WebhookScanner)EditorWindow.GetWindow(typeof(WebhookScanner));
        window.webhookScannerEnabled = true;
    }
    void OnGUI()
    {
        EditorGUILayout.Space();
        EditorGUILayout.BeginVertical();

        GUILayout.Label("Webhook Scanner Settings", EditorStyles.boldLabel);

        webhookScannerEnabled = EditorGUILayout.Toggle("Enable Webhook Scanner", webhookScannerEnabled);

        EditorGUILayout.EndVertical();
        EditorGUILayout.Space();

        if (GUILayout.Button("Scan Project for Webhooks"))
        {
            ScanProject();
        }
    }

    void OnEnable()
    {
        EditorApplication.projectWindowItemOnGUI += ScanWebhooks;
        AssetDatabase.importPackageCompleted += OnImportCompleted;
    }

    void OnDisable()
    {
        EditorApplication.projectWindowItemOnGUI -= ScanWebhooks;
        AssetDatabase.importPackageCompleted -= OnImportCompleted;
    }


    void ScanProject()
    {
        string[] assets = AssetDatabase.FindAssets("", new[] { "Assets" })
            .Select(guid => AssetDatabase.GUIDToAssetPath(guid))
            .Where(path => !string.IsNullOrEmpty(path) && !AssetDatabase.IsValidFolder(path))
            .ToArray();

        foreach (string asset in assets)
        {
            ScanResult result = ScanFile(asset);
            if (!result.success)
            {
                string message = "Webhook detected in " + asset;
                if (EditorUtility.DisplayDialog("Webhook Detected", message, "Delete", "Cancel"))
                {
                    AssetDatabase.DeleteAsset(asset);
                }
            }
        }

        AssetDatabase.Refresh();
    }


    void ScanWebhooks(string guid, Rect selectionRect)
    {
        if (!webhookScannerEnabled) return;

        string path = AssetDatabase.GUIDToAssetPath(guid);
        if (!string.IsNullOrEmpty(path) && File.Exists(path))
        {
            ScanResult result = ScanFile(path);
            if (!result.success)
            {
                GUI.backgroundColor = Color.red;
                GUI.Box(selectionRect, GUIContent.none);
            }
        }
    }

    void OnImportCompleted(string packageName)
    {
        if (!webhookScannerEnabled) return;

        string[] importedAssets = AssetDatabase.FindAssets("", new[] { "Assets" })
            .Select(guid => AssetDatabase.GUIDToAssetPath(guid))
            .Where(path => !string.IsNullOrEmpty(path) && File.Exists(path))
            .ToArray();

        foreach (string importedAsset in importedAssets)
        {
            ScanResult result = ScanFile(importedAsset);
            if (!result.success)
            {
                AssetDatabase.DeleteAsset(importedAsset);
                Debug.LogWarning(result.message);
            }
        }
    }

    private ScanResult ScanFile(string path)
    {
        if (!File.Exists(path)) return new ScanResult(false, "File not found: " + path);

        string fileContents = File.ReadAllText(path);
        if (fileContents.Contains("discord.com/api/webhooks/") || fileContents.Contains("discordapp.com/api/webhooks/") || fileContents.Contains("base64"))
        {
            return new ScanResult(false, "Webhook detected in " + path);
        }

        return new ScanResult(true, "File passed webhook scan: " + path);
    }

    private class ScanResult
    {
        public bool success;
        public string message;

        public ScanResult(bool success, string message)
        {
            this.success = success;
            this.message = message;
        }
    }
}
