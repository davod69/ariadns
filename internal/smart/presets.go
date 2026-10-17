package smart

// Category is a named group of domains that can be switched on or off.
type Category struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Default bool     `json:"default"` // enabled on first start
	Domains []string `json:"domains"`
}

// Presets is the built-in catalogue. Matching is by domain suffix, so
// "steampowered.com" also covers "store.steampowered.com".
var Presets = []Category{
	{ID: "gaming", Title: "Game platforms & launchers", Default: true, Domains: []string{
		"steampowered.com", "steamcommunity.com", "steamstatic.com", "steam-chat.com", "valvesoftware.com",
		"epicgames.com", "unrealengine.com", "ea.com", "origin.com", "battle.net", "blizzard.com",
		"ubisoft.com", "ubi.com", "riotgames.com", "leagueoflegends.com", "playvalorant.com",
		"playstation.com", "playstation.net", "sonyentertainmentnetwork.com", "xboxlive.com", "xbox.com",
		"nintendo.com", "nintendo.net", "rockstargames.com", "gog.com", "bethesda.net", "2k.com",
	}},
	{ID: "online-games", Title: "Online games", Default: true, Domains: []string{
		"callofduty.com", "activision.com", "pubg.com", "krafton.com", "supercell.com", "supercell.net",
		"minecraft.net", "mojang.com", "roblox.com", "rbxcdn.com", "faceit.com", "wargaming.net",
		"warframe.com", "digitalextremes.com", "hoyoverse.com", "mihoyo.com", "genshinimpact.com",
		"fortnite.com", "rocketleague.com", "paladins.com", "hirezstudios.com", "dota2.com",
	}},
	{ID: "anticheat", Title: "Anti-cheat services", Default: true, Domains: []string{
		"easyanticheat.net", "battleye.com", "vac-valve.com", "xigncode.com",
	}},
	{ID: "cloud-gaming", Title: "Cloud gaming", Default: false, Domains: []string{
		"geforcenow.com", "nvidiagrid.net", "nvidia.com", "xboxlive.com", "luna.amazon.com",
	}},
	{ID: "ai", Title: "AI assistants", Default: true, Domains: []string{
		"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "anthropic.com", "claude.ai",
		"gemini.google.com", "generativelanguage.googleapis.com", "aistudio.google.com", "perplexity.ai",
		"midjourney.com", "x.ai", "grok.com", "huggingface.co", "mistral.ai", "cursor.com", "cursor.sh",
		"copilot.microsoft.com", "poe.com", "character.ai", "elevenlabs.io", "runwayml.com",
	}},
	{ID: "dev", Title: "Developer registries & tools", Default: true, Domains: []string{
		"docker.io", "docker.com", "registry-1.docker.io", "npmjs.org", "npmjs.com", "pypi.org",
		"pythonhosted.org", "golang.org", "go.dev", "rubygems.org", "crates.io", "rust-lang.org",
		"jetbrains.com", "gradle.org", "maven.org", "terraform.io", "hashicorp.com", "github.com",
		"githubusercontent.com", "githubassets.com", "gitlab.com", "visualstudio.com", "vscode-cdn.net",
		"developer.android.com", "gcr.io", "ghcr.io", "quay.io", "kubernetes.io", "cloudflare.com",
	}},
	{ID: "streaming", Title: "Video & music streaming", Default: false, Domains: []string{
		"netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "spotify.com", "scdn.co",
		"twitch.tv", "ttvnw.net", "jtvnw.net", "hulu.com", "disneyplus.com", "disney-plus.net",
		"primevideo.com", "max.com", "hbomax.com", "crunchyroll.com", "soundcloud.com",
	}},
	{ID: "social", Title: "Communication & social", Default: false, Domains: []string{
		"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "reddit.com", "redd.it",
		"redditstatic.com", "slack.com", "zoom.us", "notion.so", "medium.com", "quora.com",
	}},
	{ID: "downloads", Title: "Game & app downloads (bulk traffic, off by default)", Default: false, Domains: []string{
		"steamcontent.com", "download.epicgames.com", "epicgames-download1.akamaized.net",
		"dl.battle.net", "cdn.blizzard.com", "download.ubi.com", "origin-a.akamaihd.net",
		"dl.xboxlive.com", "assets1.xboxlive.com", "gs2.ww.prod.dl.playstation.net",
	}},
}
