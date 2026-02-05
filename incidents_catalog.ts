import { ExternalResource } from './types';

const PROMPT_INJECTION_INCIDENTS: ExternalResource[] = [
  { title: "Prompt Injection attacks against LLM-integrated applications (arXiv 2306.05499)", url: "https://arxiv.org/abs/2306.05499" },
  { title: "Indirect instruction injection via images and sounds (arXiv 2307.10490)", url: "https://arxiv.org/abs/2307.10490" }
];

const INDIRECT_PROMPT_INJECTION_INCIDENTS: ExternalResource[] = [
  { title: "Compromising real-world LLM-integrated apps with indirect prompt injection (arXiv 2302.12173)", url: "https://arxiv.org/abs/2302.12173" },
  { title: "Indirect instruction injection via images and sounds (arXiv 2307.10490)", url: "https://arxiv.org/abs/2307.10490" }
];

const SYSTEM_PROMPT_LEAK_INCIDENTS: ExternalResource[] = [
  { title: "Bing Chat spills system prompt via prompt injection (Ars Technica, 2023)", url: "https://arstechnica.com/information-technology/2023/02/ai-powered-bing-chat-spills-its-secrets-via-prompt-injection-attack/" },
  { title: "Bing Chat prompt injection reveals internal codename (Gigazine, 2023)", url: "https://gigazine.net/gsc_news/en/20230214-bing-chatgpt-discloses-secrets/" }
];

const SENSITIVE_DISCLOSURE_INCIDENTS: ExternalResource[] = [
  { title: "OpenAI March 20 ChatGPT data leak (2023)", url: "https://openai.com/blog/march-20-chatgpt-outage" },
  { title: "Samsung internal data leak via ChatGPT (2023)", url: "https://techcrunch.com/2023/05/02/samsung-bans-use-of-generative-ai-tools-like-chatgpt-after-april-internal-data-leak/" }
];

const SECRET_EXPOSURE_INCIDENTS: ExternalResource[] = [
  { title: "OpenAI March 20 ChatGPT data leak (2023)", url: "https://openai.com/blog/march-20-chatgpt-outage" },
  { title: "Accenture exposed credentials in public S3 buckets (2017)", url: "https://www.helpnetsecurity.com/2017/10/10/accenture-data-exposed/" }
];

const CONTEXT_OVER_SHARING_INCIDENTS: ExternalResource[] = [
  { title: "OpenAI March 20 ChatGPT data leak (2023)", url: "https://openai.com/blog/march-20-chatgpt-outage" },
  { title: "Verizon customer data exposed via misconfigured S3 bucket (2017)", url: "https://www.techtarget.com/searchsecurity/news/450422709/Misconfigured-AWS-S3-bucket-exposes-millions-of-Verizon-customers-data" }
];

const SUPPLY_CHAIN_INCIDENTS: ExternalResource[] = [
  { title: "CISA alert on SolarWinds supply chain compromise (AA20-352A)", url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a" },
  { title: "CISA alert on 3CXDesktopApp supply chain attack (2023)", url: "https://www.cisa.gov/news-events/alerts/2023/03/30/supply-chain-attack-against-3cxdesktopapp" },
  { title: "npm event-stream incident analysis (2018)", url: "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident" }
];

const TOOL_POISONING_INCIDENTS: ExternalResource[] = [
  { title: "npm event-stream incident analysis (2018)", url: "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident" },
  { title: "ua-parser-js npm compromise (2021)", url: "https://tag-security.cncf.io/community/catalog/compromises/2021/ua-parser-js/" }
];

const DATA_POISONING_INCIDENTS: ExternalResource[] = [
  { title: "BadNets backdoor attacks (arXiv 1708.06733)", url: "https://arxiv.org/abs/1708.06733" },
  { title: "Microsoft Tay chatbot manipulated by users (2016)", url: "https://time.com/4270684/microsoft-tay-chatbot-racism/" }
];

const DATASET_POISONING_INCIDENTS: ExternalResource[] = [
  { title: "Poisoning Web-Scale Training Datasets is Practical (arXiv 2302.10149)", url: "https://arxiv.org/abs/2302.10149" },
  { title: "BadNets backdoor attacks (arXiv 1708.06733)", url: "https://arxiv.org/abs/1708.06733" }
];

const OUTPUT_HANDLING_INCIDENTS: ExternalResource[] = [
  { title: "TalkTalk breach tied to SQL injection (2015)", url: "https://www.wired.com/story/talktalk-fine-hack-400000" },
  { title: "CISA alert for Log4Shell exploitation (CVE-2021-44228)", url: "https://www.cisa.gov/news-events/alerts/2021/12/13/cisa-creates-webpage-apache-log4j-vulnerability-cve-2021-44228" }
];

const COMMAND_EXECUTION_INCIDENTS: ExternalResource[] = [
  { title: "CISA alert for Log4Shell exploitation (CVE-2021-44228)", url: "https://www.cisa.gov/news-events/alerts/2021/12/13/cisa-creates-webpage-apache-log4j-vulnerability-cve-2021-44228" },
  { title: "NVD: Shellshock command injection (CVE-2014-6271)", url: "https://nvd.nist.gov/vuln/detail/CVE-2014-6271" }
];

const MODEL_EVASION_INCIDENTS: ExternalResource[] = [
  { title: "Physical stop-sign adversarial attack (CVPR 2018)", url: "https://iotsecurity.engin.umich.edu/robust-physical-world-attacks-on-deep-learning-visual-classification/" },
  { title: "Adversarial Patch (arXiv 1712.09665)", url: "https://arxiv.org/abs/1712.09665" }
];

const MODEL_INVERSION_INCIDENTS: ExternalResource[] = [
  { title: "Model inversion attacks (ACM CCS 2015)", url: "https://doi.org/10.1145/2810103.2813677" },
  { title: "Membership inference attacks (IEEE S&P 2017)", url: "https://doi.org/10.1109/SP.2017.41" }
];

const MEMBERSHIP_INFERENCE_INCIDENTS: ExternalResource[] = [
  { title: "Membership inference attacks (IEEE S&P 2017)", url: "https://doi.org/10.1109/SP.2017.41" },
  { title: "Model inversion attacks (ACM CCS 2015)", url: "https://doi.org/10.1145/2810103.2813677" }
];

const MODEL_THEFT_INCIDENTS: ExternalResource[] = [
  { title: "Stealing ML models via prediction APIs (arXiv 1609.02943)", url: "https://arxiv.org/abs/1609.02943" },
  { title: "How to Steal an AI (Wired, 2016)", url: "https://www.wired.com/2016/09/how-to-steal-an-ai/" }
];

const MISINFORMATION_INCIDENTS: ExternalResource[] = [
  { title: "Air Canada chatbot misinformation ruling (2024)", url: "https://www.theguardian.com/world/2024/feb/16/air-canada-chatbot-lawsuit" },
  { title: "Mata v. Avianca fake citations (2023)", url: "https://www.forbes.com/sites/mollybohannon/2023/06/08/lawyer-used-chatgpt-in-court-and-cited-fake-cases-a-judge-is-considering-sanctions/" }
];

const UNBOUNDED_CONSUMPTION_INCIDENTS: ExternalResource[] = [
  { title: "GitHub hit by record DDoS attack (2018)", url: "https://www.wired.com/story/github-ddos-memcached" },
  { title: "Akamai report on 1.35 Tbps DDoS attack (2018)", url: "https://www.akamai.com/newsroom/press-release/akamai-releases-summer-2018-state-of-the-internet-security-report" }
];

const CASCADING_FAILURES_INCIDENTS: ExternalResource[] = [
  { title: "SEC charges Knight Capital over trading incident (2013)", url: "https://www.sec.gov/newsroom/press-releases/2013-222" },
  { title: "Knight Capital trading glitch losses (2012)", url: "https://www.cnbc.com/2012/10/17/knight-capital-posts-3q-loss-on-software-glitch.html" }
];

const EXCESSIVE_AGENCY_INCIDENTS: ExternalResource[] = [
  { title: "SEC charges Knight Capital over trading incident (2013)", url: "https://www.sec.gov/newsroom/press-releases/2013-222" },
  { title: "Capital One breach via SSRF and IAM access (2019)", url: "https://www.cnbc.com/2019/10/24/senators-urge-investigation-of-amazons-role-in-capital-one-hack.html" }
];

const AUTHZ_INCIDENTS: ExternalResource[] = [
  { title: "Capital One breach via SSRF and IAM access (2019)", url: "https://www.cnbc.com/2019/10/24/senators-urge-investigation-of-amazons-role-in-capital-one-hack.html" },
  { title: "NVD: Apache HBase REST authorization flaw (CVE-2019-0212)", url: "https://nvd.nist.gov/vuln/detail/CVE-2019-0212" }
];

const AUDIT_TELEMETRY_INCIDENTS: ExternalResource[] = [
  { title: "Uber breach concealment indictment (2016/2017)", url: "https://www.wired.com/story/uber-exec-joe-sullivan-data-breach-indictment/" },
  { title: "TalkTalk breach and monitoring failures (2015)", url: "https://www.wired.com/story/talktalk-fine-hack-400000" }
];

const SHADOW_IT_INCIDENTS: ExternalResource[] = [
  { title: "Accenture exposed credentials in public S3 buckets (2017)", url: "https://www.helpnetsecurity.com/2017/10/10/accenture-data-exposed/" },
  { title: "Verizon customer data exposed via misconfigured S3 bucket (2017)", url: "https://www.techtarget.com/searchsecurity/news/450422709/Misconfigured-AWS-S3-bucket-exposes-millions-of-Verizon-customers-data" }
];

const UNAUTHORIZED_TRAINING_DATA_INCIDENTS: ExternalResource[] = [
  { title: "NYT sues OpenAI and Microsoft over training data (2023)", url: "https://www.theguardian.com/media/2023/dec/27/new-york-times-openai-microsoft-lawsuit" },
  { title: "Getty Images v. Stability AI trial (2025)", url: "https://apnews.com/article/580ba200a3296c87207983f04cda4680" }
];

const DATA_HANDLING_INCIDENTS: ExternalResource[] = [
  { title: "OpenAI required to retain deleted chats (2024)", url: "https://www.theverge.com/news/681280/openai-storing-deleted-chats-nyt-lawsuit" },
  { title: "Verizon customer data exposed via misconfigured S3 bucket (2017)", url: "https://www.techtarget.com/searchsecurity/news/450422709/Misconfigured-AWS-S3-bucket-exposes-millions-of-Verizon-customers-data" }
];

const OUTPUT_INTEGRITY_INCIDENTS: ExternalResource[] = [
  { title: "Stuxnet and manipulation of industrial control systems (2013)", url: "https://www.theguardian.com/technology/2013/feb/26/symantec-us-computer-virus-iran-nuclear" },
  { title: "Stuxnet analysis and Natanz impact (2011)", url: "https://isis-online.org/isis-reports/detail/stuxnet-malware-and-natanz-update-of-isis-december-22-2010-reportsupa-href1/8%26lang%3Den" }
];

const MODEL_SKEWING_INCIDENTS: ExternalResource[] = [
  { title: "Microsoft Tay chatbot manipulated by users (2016)", url: "https://time.com/4270684/microsoft-tay-chatbot-racism/" },
  { title: "Bing AI behavior issues in long chats (2023)", url: "https://time.com/6256529/bing-openai-chatgpt-danger-alignment/" }
];

export const INCIDENTS_BY_THREAT_ID: Record<string, ExternalResource[]> = {
  // LLM Top 10
  "LLM01:2025": PROMPT_INJECTION_INCIDENTS,
  "LLM02:2025": SENSITIVE_DISCLOSURE_INCIDENTS,
  "LLM03:2025": SUPPLY_CHAIN_INCIDENTS,
  "LLM04:2025": DATA_POISONING_INCIDENTS,
  "LLM05:2025": OUTPUT_HANDLING_INCIDENTS,
  "LLM06:2025": EXCESSIVE_AGENCY_INCIDENTS,
  "LLM07:2025": SYSTEM_PROMPT_LEAK_INCIDENTS,
  "LLM08:2025": INDIRECT_PROMPT_INJECTION_INCIDENTS,
  "LLM09:2025": MISINFORMATION_INCIDENTS,
  "LLM10:2025": UNBOUNDED_CONSUMPTION_INCIDENTS,

  // ML Top 10
  "ML01:2023": MODEL_EVASION_INCIDENTS,
  "ML02:2023": DATA_POISONING_INCIDENTS,
  "ML03:2023": MODEL_INVERSION_INCIDENTS,
  "ML04:2023": MEMBERSHIP_INFERENCE_INCIDENTS,
  "ML05:2023": MODEL_THEFT_INCIDENTS,
  "ML06:2023": SUPPLY_CHAIN_INCIDENTS,
  "ML07:2023": DATASET_POISONING_INCIDENTS,
  "ML08:2023": MODEL_SKEWING_INCIDENTS,
  "ML09:2023": OUTPUT_INTEGRITY_INCIDENTS,
  "ML10:2023": DATA_POISONING_INCIDENTS,

  // Agentic AI (ASI)
  "ASI01": PROMPT_INJECTION_INCIDENTS,
  "ASI02": EXCESSIVE_AGENCY_INCIDENTS,
  "ASI03": AUTHZ_INCIDENTS,
  "ASI04": SUPPLY_CHAIN_INCIDENTS,
  "ASI05": COMMAND_EXECUTION_INCIDENTS,
  "ASI06": INDIRECT_PROMPT_INJECTION_INCIDENTS,
  "ASI07": AUTHZ_INCIDENTS,
  "ASI08": CASCADING_FAILURES_INCIDENTS,
  "ASI09": MISINFORMATION_INCIDENTS,
  "ASI10": EXCESSIVE_AGENCY_INCIDENTS,

  // SAIF Risks
  "SAIF-R01": DATA_POISONING_INCIDENTS,
  "SAIF-R02": UNAUTHORIZED_TRAINING_DATA_INCIDENTS,
  "SAIF-R03": SUPPLY_CHAIN_INCIDENTS,
  "SAIF-R04": DATA_HANDLING_INCIDENTS,
  "SAIF-R05": MODEL_THEFT_INCIDENTS,
  "SAIF-R06": SUPPLY_CHAIN_INCIDENTS,
  "SAIF-R07": UNBOUNDED_CONSUMPTION_INCIDENTS,
  "SAIF-R08": MODEL_THEFT_INCIDENTS,
  "SAIF-R09": COMMAND_EXECUTION_INCIDENTS,
  "SAIF-R10": PROMPT_INJECTION_INCIDENTS,
  "SAIF-R11": MODEL_EVASION_INCIDENTS,
  "SAIF-R12": SENSITIVE_DISCLOSURE_INCIDENTS,
  "SAIF-R13": MODEL_INVERSION_INCIDENTS,
  "SAIF-R14": OUTPUT_HANDLING_INCIDENTS,
  "SAIF-R15": EXCESSIVE_AGENCY_INCIDENTS,

  // MCP Top 10
  "MCP1:2025": SECRET_EXPOSURE_INCIDENTS,
  "MCP2:2025": AUTHZ_INCIDENTS,
  "MCP03:2025": TOOL_POISONING_INCIDENTS,
  "MCP4:2025": SUPPLY_CHAIN_INCIDENTS,
  "MCP5:2025": COMMAND_EXECUTION_INCIDENTS,
  "MCP6:2025": INDIRECT_PROMPT_INJECTION_INCIDENTS,
  "MCP07:2025": AUTHZ_INCIDENTS,
  "MCP8:2025": AUDIT_TELEMETRY_INCIDENTS,
  "MCP9:2025": SHADOW_IT_INCIDENTS,
  "MCP10:2025": CONTEXT_OVER_SHARING_INCIDENTS
};
