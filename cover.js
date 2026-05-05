/*!
 * 源文件 https://github.com/powerfullz/override-rules
 *
 * - ipv6: 启用 IPv6 支持（默认 false）
 * - quic: 允许 QUIC 流量（UDP 443，默认 false）
*/

function parseBool(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    return value.toLowerCase() === "true" || value === "1";
  }
  return false;
}

/**
 * 解析传入的脚本参数，并将其转换为内部使用的功能开关（feature flags）。
 * @param {object} args - 传入的原始参数对象，如 $arguments。
 * @returns {object} - 包含所有功能开关状态的对象。
 *
 * 该函数通过一个 `spec` 对象定义了外部参数名（如 `quic`）到内部变量名（如 `quicEnabled`）的映射关系。
 * 它会遍历 `spec` 中的每一项，对 `args` 对象中对应的参数值调用 `parseBool` 函数进行布尔化处理，
 * 并将结果存入返回的对象中。
 */
function buildFeatureFlags(args) {
  const spec = {
    ipv6: "ipv6Enabled",
    quic: "quicEnabled",
  };

  const flags = Object.entries(spec).reduce((acc, [sourceKey, targetKey]) => {
    acc[targetKey] = parseBool(args[sourceKey]) || false;
    return acc;
  }, {});

  return flags;
}

const rawArgs = typeof $arguments !== "undefined" ? $arguments : {};
const {
  ipv6Enabled,
  quicEnabled,
} = buildFeatureFlags(rawArgs);

const PROXY_GROUPS = {
  SELECT: "选择代理",
  SELF: "自建节点",
  DESIGN: "设计网站",
  AI: "大模型",
  DIRECT: "直连",
};

function buildBaseLists({ proxyNames, hasSelfProxyGroup }) {
  const buildList = (...elements) => elements.flat().filter(Boolean);

  /**
   * "选择代理"组的顶层候选列表：自建节点 -> 所有订阅节点 -> 直连。
   */
  const defaultSelector = buildList(
    hasSelfProxyGroup && PROXY_GROUPS.SELF,
    proxyNames,
    PROXY_GROUPS.DIRECT
  );

  /**
   * 大多数策略组的通用候选列表：选择代理 → 直连。
   */
  const defaultProxies = buildList(
    PROXY_GROUPS.SELECT,
    PROXY_GROUPS.DIRECT
  );

  return { defaultProxies, defaultSelector };
}

const FEATURE_GROUP_TEMPLATES = [
  {
    name: PROXY_GROUPS.AI,
    icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/chatgpt.png",
  },
  {
    name: "Google",
    icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Google.png",
  },
  {
    name: "YouTube",
    icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/YouTube.png",
  },
  {
    name: PROXY_GROUPS.DESIGN,
    icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Behance.png",
  },
];

const RULE_PROVIDERS = {
  ADBlock: {
    type: "http",
    behavior: "domain",
    format: "mrs",
    interval: 86400,
    url: "https://adrules.top/adrules-mihomo.mrs",
    path: "./ruleset/ADBlock.mrs",
  },
  GoogleFCM: {
    type: "http",
    behavior: "classical",
    format: "text",
    interval: 86400,
    url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list",
    path: "./ruleset/FirebaseCloudMessaging.list",
  },
  AdditionalFilter: {
    type: "http",
    behavior: "classical",
    format: "text",
    interval: 86400,
    url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list",
    path: "./ruleset/AdditionalFilter.list",
  },
};

const DESIGN_SITE_DOMAINS = [
  "figma.com",
  "figma.net",
  "framer.com",
  "webflow.com",
  "canva.com",
  "adobe.com",
  "adobe.io",
  "behance.net",
  "dribbble.com",
  "sketch.com",
  "lottiefiles.com",
  "iconify.design",
  "uizard.io",
];

const AI_SITE_DOMAINS = [
  "openai.com",
  "chatgpt.com",
  "cdn.openai.com",
  "images.openai.com",
  "oaistatic.com",
  "oaiusercontent.com",
  "anthropic.com",
  "claude.ai",
  "perplexity.ai",
  "poe.com",
  "copilot.microsoft.com",
  "bing.com",
  "bingapis.com",
  "grok.com",
  "x.ai",
  "mistral.ai",
  "deepseek.com",
  "qwen.ai",
  "tongyi.com",
  "kimi.moonshot.cn",
  "moonshot.cn",
  "doubao.com",
  "volcengine.com",
  "huggingface.co",
  "ideogram.ai",
  "ideogram.com",
  "ideogramcdn.com",
];

const TRUSTED_ASSET_DOMAINS = [
  "ctfassets.net",
  "imgix.net",
  "cloudfront.net",
  "akamaihd.net",
  "fastly.net",
  "jsdelivr.net",
  "unpkg.com",
  "gstatic.com",
  "googleapis.com",
  "googleusercontent.com",
  "githubusercontent.com",
  "githubassets.com",
  "vercel.app",
  "vercel-insights.com",
  "sentry.io",
  "sentry-cdn.com",
  "stripe.com",
  "stripe.network",
];

const PASSKEY_DOMAINS = [
  "cable.ua5v.com",
  "cable.auth.com",
  "app-site-association.cdn-apple.com",
  "app-site-association.networking.apple",
  "apple.com",
  "icloud.com",
];

const buildDomainSuffixRules = (domains, policy) =>
  domains.map((domain) => `DOMAIN-SUFFIX,${domain},${policy}`);

const BASE_RULES = [
  `RULE-SET,ADBlock,广告拦截`,
  `RULE-SET,AdditionalFilter,广告拦截`,
  `RULE-SET,GoogleFCM,${PROXY_GROUPS.DIRECT}`,
  `DOMAIN,services.googleapis.cn,${PROXY_GROUPS.SELECT}`,
  "GEOSITE,YOUTUBE,YouTube",
  "GEOSITE,GOOGLE,Google",
  ...buildDomainSuffixRules(DESIGN_SITE_DOMAINS, PROXY_GROUPS.DESIGN),
  ...buildDomainSuffixRules(AI_SITE_DOMAINS, PROXY_GROUPS.AI),
  ...buildDomainSuffixRules(PASSKEY_DOMAINS, PROXY_GROUPS.DIRECT),
  ...buildDomainSuffixRules(TRUSTED_ASSET_DOMAINS, PROXY_GROUPS.SELECT),
  `GEOSITE,PRIVATE,${PROXY_GROUPS.DIRECT}`,
  `GEOIP,PRIVATE,${PROXY_GROUPS.DIRECT}`,
  `MATCH,${PROXY_GROUPS.DIRECT}`,
];

function buildRules({ quicEnabled }) {
  const ruleList = [...BASE_RULES];

  if (!quicEnabled) {
    /**
     * 屏蔽 UDP 443（QUIC）流量。
     * 部分网络环境下 UDP 性能不稳定，禁用 QUIC 可强制回退到 TCP，改善整体体验。
     */
    ruleList.unshift("AND,((DST-PORT,443),(NETWORK,UDP)),REJECT");
  }

  return ruleList;
}

const snifferConfig = {
  "enable": true,
  "override-destination": true,
  "force-dns-mapping": true,
  sniff: {
    TLS: {
      ports: [443, 8443],
    },
    HTTP: {
      ports: [80, 8080, 8880],
    },
    QUIC: {
      ports: [443, 8443],
    },
  }
};

function buildDnsConfig({ ipv6Enabled }) {
  const config = {
    "enable": true,
    "ipv6": ipv6Enabled,
    "prefer-h3": false,
    "enhanced-mode": "fake-ip",
    "default-nameserver": ["119.29.29.29", "223.5.5.5"],
    "nameserver": ["system", "223.5.5.5", "119.29.29.29", "180.184.1.1"],
    "fallback": [
      "quic://dns0.eu",
      "https://dns.cloudflare.com/dns-query",
      "https://dns.sb/dns-query",
      "tcp://208.67.222.222",
      "tcp://8.26.56.2",
    ],
    "proxy-server-nameserver": ["https://dns.alidns.com/dns-query", "tls://dot.pub"],
    "fake-ip-filter": [
      "geosite:private",
      "geosite:connectivity-check",
      "geosite:cn",
      "*.icloud.com",
      "*.stun.*.*",
      "*.stun.*.*.*",
    ],
  };

  return config;
}

function buildSelfProxyGroup(config) {
  const proxies = config.proxies || [];
  const nodes = proxies
    .map((proxy) => proxy.name || "")
    .filter((name) => /^self-tts/.test(name))
    .sort((a, b) => Number(!/main/i.test(a)) - Number(!/main/i.test(b)));

  if (nodes.length === 0) {
    return null;
  }

  return {
    name: PROXY_GROUPS.SELF,
    icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Bypass.png",
    type: "select",
    proxies: [...nodes, PROXY_GROUPS.DIRECT],
  };
}

function buildProxyGroups({ selfProxyGroup, defaultProxies, defaultSelector }) {
  const featureGroups = FEATURE_GROUP_TEMPLATES.map((template) => ({
    name: template.name,
    icon: template.icon,
    type: "select",
    proxies: defaultProxies,
  }));

  return [
    {
      name: PROXY_GROUPS.SELECT,
      icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
      type: "select",
      proxies: defaultSelector,
    },
    selfProxyGroup,
    ...featureGroups,
    {
      name: PROXY_GROUPS.DIRECT,
      icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png",
      type: "select",
      proxies: ["DIRECT"],
    },
    {
      name: "广告拦截",
      icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/AdBlack.png",
      type: "select",
      proxies: ["REJECT", "REJECT-DROP", PROXY_GROUPS.DIRECT],
    },
  ].filter(Boolean);
}

function main(config) {
  const proxies = config && Array.isArray(config.proxies) ? config.proxies : [];
  const resultConfig = { proxies };

  const selfProxyGroup = buildSelfProxyGroup(resultConfig);
  const proxyNames = proxies
    .map((proxy) => proxy.name || "")
    .filter((name) => name && !/^self-tts/.test(name));

  const { defaultProxies, defaultSelector } = buildBaseLists({
    proxyNames,
    hasSelfProxyGroup: Boolean(selfProxyGroup),
  });

  const proxyGroups = buildProxyGroups({
    selfProxyGroup,
    defaultProxies,
    defaultSelector,
  });

  const globalProxies = proxyGroups.map((item) => item.name);
  proxyGroups.push({
    name: "GLOBAL",
    icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png",
    "include-all": true,
    type: "select",
    proxies: globalProxies,
  });

  const finalRules = buildRules({ quicEnabled });
  const dnsConfig = buildDnsConfig({ ipv6Enabled });

  Object.assign(resultConfig, {
    "proxy-groups": proxyGroups,
    "rule-providers": RULE_PROVIDERS,
    "rules": finalRules,
    "sniffer": snifferConfig,
    "dns": dnsConfig,
    "geodata-mode": true,
    "geox-url": {
      "geoip": "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
      "geosite": "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
      "mmdb": "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb",
      "asn": "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb",
    },
  });

  return resultConfig;
} 
