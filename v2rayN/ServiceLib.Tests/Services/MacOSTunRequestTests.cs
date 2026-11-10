namespace ServiceLib.Tests.Services;

public class MacOSTunRequestTests
{
    private static readonly string Secret = new('A', 64);

    [Test]
    [Arguments(ECoreType.sing_box, "sing-box")]
    [Arguments(ECoreType.Xray, "xray")]
    [Arguments(ECoreType.mihomo, "mihomo")]
    public async Task CoreName_UsesFixedAllowlist(ECoreType core, string name)
    {
        await MacOSTunRequest.CoreName(core).Should().BeEqualTo(name);
    }

    [Test]
    public async Task UnsupportedCore_IsRejected()
    {
        var rejected = false;
        try { MacOSTunRequest.CoreName(ECoreType.naiveproxy); }
        catch (NotSupportedException) { rejected = true; }
        await rejected.Should().BeTrue();
    }

    [Test]
    public async Task MihomoYaml_PreservesQuotedStringsAndScalarTypes()
    {
        var config = MacOSTunRequest.ParseConfig(ECoreType.mihomo, """
            mixed-port: 10808
            allow-lan: false
            secret: "012345"
            proxies:
              - name: 'true'
                port: 443
            """);
        await config["mixed-port"]!.GetValue<long>().Should().BeEqualTo(10808);
        await config["allow-lan"]!.GetValue<bool>().Should().BeFalse();
        await config["secret"]!.GetValue<string>().Should().BeEqualTo("012345");
        await config["proxies"]![0]!["name"]!.GetValue<string>().Should().BeEqualTo("true");
    }

    [Test]
    public async Task ProtectController_UsesMemorySecretAndPrivateCache()
    {
        var config = JsonNode.Parse("""
            {"experimental":{"clash_api":{"external_controller":"127.0.0.1:19090"},"cache_file":{"path":"/user/cache.db"}}}
            """)!.AsObject();
        MacOSTunRequest.ProtectController(ECoreType.sing_box, config, Secret);
        await config["experimental"]!["clash_api"]!["secret"]!.GetValue<string>().Should().BeEqualTo(Secret);
        await config["experimental"]!["cache_file"]!["path"]!.GetValue<string>().Should().BeEqualTo("cache.db");
    }

    [Test]
    public async Task WeakControllerSecret_IsRejected()
    {
        var rejected = false;
        try { MacOSTunRequest.ProtectController(ECoreType.mihomo, new JsonObject(), "password"); }
        catch (ArgumentException) { rejected = true; }
        await rejected.Should().BeTrue();
    }

    [Test]
    public async Task OversizedConfig_IsRejectedBeforeParsing()
    {
        var rejected = false;
        try { MacOSTunRequest.ParseConfig(ECoreType.sing_box, new string(' ', MacOSTunRequest.MaxConfigBytes + 1)); }
        catch (InvalidDataException) { rejected = true; }
        await rejected.Should().BeTrue();
    }

    [Test]
    public async Task StartRequest_SnapshotsInputBytesAndNeverSendsExecutableOrEnvironment()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"v2rayn-tun-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var configPath = Path.Combine(directory, "config.json");
        var assetPath = Path.Combine(directory, "rules.srs");
        try
        {
            await File.WriteAllBytesAsync(assetPath, [1, 2, 3, 4]);
            var config = new JsonObject
            {
                ["route"] = new JsonObject
                {
                    ["rule_set"] = new JsonArray(new JsonObject { ["type"] = "local", ["path"] = assetPath }),
                },
                ["log"] = new JsonObject { ["output"] = "/user/gui.log" },
            };
            await File.WriteAllTextAsync(configPath, config.ToJsonString());
            var request = JsonNode.Parse(await MacOSTunRequest.CreateStartAsync(ECoreType.sing_box, configPath, Secret))!.AsObject();
            await request["core"]!.GetValue<string>().Should().BeEqualTo("sing-box");
            await request.ContainsKey("executable").Should().BeFalse();
            await request.ContainsKey("arguments").Should().BeFalse();
            await request.ContainsKey("environment").Should().BeFalse();
            await request.ContainsKey("pid").Should().BeFalse();
            await request.ToJsonString().Contains(directory).Should().BeFalse();
            await request["config"]!["log"]!.AsObject().ContainsKey("output").Should().BeFalse();
            var relative = request["config"]!["route"]!["rule_set"]![0]!["path"]!.GetValue<string>();
            await relative.StartsWith("assets/").Should().BeTrue();
            var name = relative["assets/".Length..];
            var content = request["assets"]![name]!.GetValue<string>();
            await Convert.FromBase64String(content).SequenceEqual(new byte[] { 1, 2, 3, 4 }).Should().BeTrue();
            // The ordinary GUI config is unchanged and does not contain the API token.
            await (await File.ReadAllTextAsync(configPath)).Contains(Secret).Should().BeFalse();
        }
        finally
        {
            File.Delete(configPath);
            File.Delete(assetPath);
            Directory.Delete(directory);
        }
    }
}
