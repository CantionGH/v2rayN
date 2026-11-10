using System.Globalization;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace ServiceLib.Services;

/// <summary>
/// Unprivileged preparation only. The daemon independently validates the payload;
/// it never opens a user-provided config/asset pathname or executes its arguments.
/// </summary>
public static class MacOSTunRequest
{
    public const int MaxConfigBytes = 8 * 1024 * 1024;
    public const int MaxAssetBytes = 32 * 1024 * 1024;
    public const int MaxTotalAssetBytes = 64 * 1024 * 1024;

    public static string CoreName(ECoreType coreType) => coreType switch
    {
        ECoreType.sing_box => "sing-box",
        ECoreType.Xray => "xray",
        ECoreType.mihomo => "mihomo",
        _ => throw new NotSupportedException($"Unsupported macOS TUN core: {coreType}"),
    };

    public static async Task<string> CreateStartAsync(ECoreType coreType, string configPath, string apiSecret)
    {
        var core = CoreName(coreType);
        var file = new FileInfo(configPath);
        if (file.Length > MaxConfigBytes)
        {
            throw new InvalidDataException("The TUN configuration is too large.");
        }
        var text = await File.ReadAllTextAsync(configPath);
        var config = ParseConfig(coreType, text);
        ProtectController(coreType, config, apiSecret);
        // Stream privileged logs through XPC, never open a GUI-supplied output
        // filename as root. Existing GUI log handling receives these messages.
        if (config["log"] is JsonObject log)
        {
            if (coreType == ECoreType.sing_box) { log.Remove("output"); }
            if (coreType == ECoreType.Xray) { log.Remove("access"); log.Remove("error"); }
        }
        var assets = new JsonObject();
        var total = 0L;

        async Task SnapshotFiles(JsonNode? node, int depth = 0)
        {
            if (depth > 64)
            {
                throw new InvalidDataException("The TUN configuration is too deeply nested.");
            }
            if (node is JsonObject obj)
            {
                foreach (var (key, value) in obj.ToList())
                {
                    if (value is JsonValue scalar && scalar.TryGetValue<string>(out var path)
                        && IsFileKey(key) && Path.IsPathRooted(path))
                    {
                        // Reads happen with the GUI user's privileges. Root sees only
                        // immutable bytes, never this pathname (including symlinks).
                        var info = new FileInfo(path);
                        if (!info.Exists || info.Length > MaxAssetBytes || total + info.Length > MaxTotalAssetBytes)
                        {
                            throw new InvalidDataException($"Unsupported or oversized TUN file: {key}");
                        }
                        // Bound the actual read too: the file can change after stat.
                        using var input = File.OpenRead(path);
                        using var memory = new MemoryStream();
                        var buffer = new byte[81920];
                        int count;
                        while ((count = await input.ReadAsync(buffer)) > 0)
                        {
                            if (memory.Length + count > MaxAssetBytes || total + memory.Length + count > MaxTotalAssetBytes)
                            {
                                throw new InvalidDataException("TUN assets exceed the size limit.");
                            }
                            memory.Write(buffer, 0, count);
                        }
                        var bytes = memory.ToArray();
                        var name = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() + ".data";
                        if (!assets.ContainsKey(name))
                        {
                            if (assets.Count >= 256)
                            {
                                throw new InvalidDataException("Too many TUN assets.");
                            }
                            assets[name] = Convert.ToBase64String(bytes);
                            total += bytes.Length;
                        }
                        obj[key] = $"assets/{name}";
                    }
                    else
                    {
                        await SnapshotFiles(value, depth + 1);
                    }
                }
            }
            else if (node is JsonArray array)
            {
                foreach (var item in array)
                {
                    await SnapshotFiles(item, depth + 1);
                }
            }
        }

        await SnapshotFiles(config);
        var request = new JsonObject
        {
            ["operation"] = "start",
            ["core"] = core,
            ["config"] = config,
            ["assets"] = assets,
        };
        // XPC is not an HTML context. Avoid expanding '+' and non-ASCII values
        // into \u escapes, which could otherwise inflate bounded asset payloads.
        return request.ToJsonString(new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    public static JsonObject ParseConfig(ECoreType coreType, string text)
    {
        if (Encoding.UTF8.GetByteCount(text) > MaxConfigBytes)
        {
            throw new InvalidDataException("The TUN configuration is too large.");
        }
        if (coreType != ECoreType.mihomo)
        {
            return JsonNode.Parse(text, documentOptions: new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
                MaxDepth = 64,
            }) as JsonObject ?? throw new InvalidDataException("Expected a JSON configuration object.");
        }

        var yaml = new YamlStream();
        yaml.Load(new StringReader(text));
        if (yaml.Documents.Count != 1)
        {
            throw new InvalidDataException("Expected one YAML document.");
        }
        return ConvertYaml(yaml.Documents[0].RootNode, 0) as JsonObject
            ?? throw new InvalidDataException("Expected a YAML configuration mapping.");
    }

    private static JsonNode? ConvertYaml(YamlNode node, int depth)
    {
        if (depth > 64)
        {
            throw new InvalidDataException("The YAML configuration is too deeply nested.");
        }
        switch (node)
        {
            case YamlMappingNode mapping:
                var obj = new JsonObject();
                foreach (var (key, value) in mapping.Children)
                {
                    var name = (key as YamlScalarNode)?.Value ?? throw new InvalidDataException("Non-scalar YAML key.");
                    obj.Add(name, ConvertYaml(value, depth + 1));
                }
                return obj;
            case YamlSequenceNode sequence:
                var array = new JsonArray();
                foreach (var item in sequence.Children)
                {
                    array.Add(ConvertYaml(item, depth + 1));
                }
                return array;
            case YamlScalarNode scalar:
                var text = scalar.Value;
                if (scalar.Style is not (ScalarStyle.SingleQuoted or ScalarStyle.DoubleQuoted))
                {
                    if (text is null or "null" or "Null" or "NULL" or "~") { return null; }
                    if (bool.TryParse(text, out var boolean)) { return JsonValue.Create(boolean); }
                    if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var integer)) { return JsonValue.Create(integer); }
                    if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var number) && double.IsFinite(number)) { return JsonValue.Create(number); }
                }
                return JsonValue.Create(text);
            default:
                throw new InvalidDataException("Unsupported YAML node.");
        }
    }

    private static bool IsFileKey(string key) => key.Equals("path", StringComparison.OrdinalIgnoreCase)
        || key.EndsWith("file", StringComparison.OrdinalIgnoreCase)
        || key.EndsWith("_path", StringComparison.OrdinalIgnoreCase)
        || key is "ca" or "certificate" or "private-key";

    public static void ProtectController(ECoreType coreType, JsonObject config, string secret)
    {
        if (secret.Length != 64 || !secret.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("A 256-bit controller secret is required.", nameof(secret));
        }
        if (coreType == ECoreType.sing_box && config["experimental"] is JsonObject experimental)
        {
            if (experimental["clash_api"] is JsonObject controller)
            {
                controller["secret"] = secret;
            }
            if (experimental["cache_file"] is JsonObject cache)
            {
                cache["path"] = "cache.db";
            }
        }
        else if (coreType == ECoreType.mihomo)
        {
            config["secret"] = secret;
        }
    }
}
