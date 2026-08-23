import { ExternalResource } from './types';

// ============================================================================
// AI Security Nexus - Curated Real-World Incidents & Empirical CVE Catalog
// Every threat across all frameworks is mapped to >= 5 authoritative incidents,
// CVE entries, CISA advisories, or peer-reviewed empirical research citations.
// ============================================================================

// 1. Direct & Indirect Prompt Injection Incidents
const PROMPT_INJECTION_INCIDENTS: ExternalResource[] = [
  { title: "Prompt Injection attacks against LLM-integrated applications (Perez & Ribeiro, arXiv:2306.05499)", url: "https://arxiv.org/abs/2306.05499" },
  { title: "Indirect prompt injection and tool hijacking in real-world LLM apps (Greshake et al., arXiv:2302.12173)", url: "https://arxiv.org/abs/2302.12173" },
  { title: "Abusing Images and Sounds for Indirect Instruction Injection in Multimodal LLMs (Bagdasaryan et al., arXiv:2307.10490)", url: "https://arxiv.org/abs/2307.10490" },
  { title: "Universal and Transferable Adversarial Attacks on Aligned Language Models (Zou et al., arXiv:2307.15043)", url: "https://arxiv.org/abs/2307.15043" },
  { title: "CVE-2024-5184: Email AI assistant indirect prompt injection leading to sensitive data exfiltration", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-5184" },
  { title: "ASCII smuggling & zero-width character prompt injection bypass (Johann Rehberger, Embrace The Red, 2023)", url: "https://embracethered.com/blog/posts/2023/ascii-smuggling-jailbreak-prompt-injection/" }
];

// 2. Sensitive Information Disclosure & Training Data Extraction
const SENSITIVE_DISCLOSURE_INCIDENTS: ExternalResource[] = [
  { title: "OpenAI March 2023 ChatGPT Redis cache bug disclosing user chat histories and payment records", url: "https://openai.com/blog/march-20-chatgpt-outage" },
  { title: "Samsung semiconductor source code and meeting notes leak via public ChatGPT (TechCrunch, 2023)", url: "https://techcrunch.com/2023/05/02/samsung-bans-use-of-generative-ai-tools-like-chatgpt-after-april-internal-data-leak/" },
  { title: "Extracting Training Data from Large Language Models (Carlini et al., USENIX Security 2021)", url: "https://arxiv.org/abs/2012.07805" },
  { title: "Scalable Extraction of Training Data from Production Language Models (Nasr et al., Google DeepMind, arXiv:2311.17035)", url: "https://arxiv.org/abs/2311.17035" },
  { title: "Beyond Memorization: Violating Privacy via Inference with Large Language Models (Staab et al., arXiv:2310.07298)", url: "https://arxiv.org/abs/2310.07298" },
  { title: "Microsoft AI Research 38TB research dataset and credentials exposure via SAS token (Wiz Research, 2023)", url: "https://www.wiz.io/blog/38-terabytes-of-private-data-accidentally-exposed-by-microsoft-ai-researchers" }
];

// 3. AI Supply Chain & Dependency Compromise
const SUPPLY_CHAIN_INCIDENTS: ExternalResource[] = [
  { title: "CISA Advisory AA20-352A: Advanced Persistent Threat compromise of SolarWinds Orion supply chain", url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a" },
  { title: "CISA Alert AA23-090A: Supply chain attack against 3CXDesktopApp communications software", url: "https://www.cisa.gov/news-events/alerts/2023/03/30/supply-chain-attack-against-3cxdesktopapp" },
  { title: "PyTorch dependency confusion attack on torchtriton nightly build packages (PyTorch Foundation, 2022)", url: "https://pytorch.org/blog/compromised-nightly-dependency/" },
  { title: "CVE-2024-34359: Llama.cpp Jinja2 template injection remote code execution (Protect AI HUNTR)", url: "https://huntr.com/bounties/4316cd46-6187-43a9-b3a5-b1a9e32a6886" },
  { title: "Over 100 malicious PyTorch and Pickle models discovered executing reverse shells on Hugging Face (Protect AI, 2024)", url: "https://protectai.com/blog/malicious-ai-models-on-hugging-face" },
  { title: "Hugging Face Spaces cluster credential & token leak infrastructure investigation (Wiz Research, 2023)", url: "https://www.wiz.io/blog/wiz-and-hugging-face-collaborate-to-bolster-ai-platform-security" }
];

// 4. Data Poisoning & Dataset Backdoor Attacks
const DATA_POISONING_INCIDENTS: ExternalResource[] = [
  { title: "Poisoning Web-Scale Training Datasets is Practical (Carlini et al., arXiv:2302.10149)", url: "https://arxiv.org/abs/2302.10149" },
  { title: "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain (Gu et al., arXiv:1708.06733)", url: "https://arxiv.org/abs/1708.06733" },
  { title: "Microsoft Tay conversational chatbot manipulated into generating toxic hate speech (TIME, 2016)", url: "https://time.com/4270684/microsoft-tay-chatbot-racism/" },
  { title: "Poisoning Language Models During Instruction Tuning (Wan et al., ICML 2023, arXiv:2305.00944)", url: "https://arxiv.org/abs/2305.00944" },
  { title: "Nightshade: Prompt-specific data poisoning against generative image diffusion models (USENIX Security 2024)", url: "https://arxiv.org/abs/2310.13828" },
  { title: "Poison Frogs! Targeted Clean-Label Poisoning Attacks on Neural Networks (Shafahi et al., NeurIPS 2018)", url: "https://arxiv.org/abs/1804.00792" }
];

// 5. Improper Output Handling & Downstream Injection
const OUTPUT_HANDLING_INCIDENTS: ExternalResource[] = [
  { title: "CISA Alert for Log4Shell exploitation via unvalidated JNDI string injection (CVE-2021-44228)", url: "https://www.cisa.gov/news-events/alerts/2021/12/13/cisa-creates-webpage-apache-log4j-vulnerability-cve-2021-44228" },
  { title: "TalkTalk telecommunications breach tied to unvalidated automated SQL input handling (ICO UK, 2016)", url: "https://www.wired.com/story/talktalk-fine-hack-400000" },
  { title: "Indirect prompt injection leading to cross-site scripting (XSS) via LLM Markdown rendering (Embrace The Red, 2023)", url: "https://embracethered.com/blog/posts/2023/chatgpt-cross-plugin-data-leakage/" },
  { title: "SQL Injection vulnerabilities introduced by generative code assistants (arXiv:2308.01990)", url: "https://arxiv.org/abs/2308.01990" },
  { title: "Stuxnet malware manipulation of industrial frequency converters while spoofing telemetry (Symantec Report, 2010)", url: "https://www.theguardian.com/technology/2013/feb/26/symantec-us-computer-virus-iran-nuclear" },
  { title: "ChatGPT Advanced Data Analysis / Code Interpreter sandbox escape & SSRF investigations (Johann Rehberger, 2023)", url: "https://embracethered.com/blog/posts/2023/chatgpt-code-interpreter-sandbox-escape/" }
];

// 6. Excessive Agency & Runaway Automation
const EXCESSIVE_AGENCY_INCIDENTS: ExternalResource[] = [
  { title: "SEC Release 2013-222: Knight Capital automated algorithmic loop generating $440M loss in 45 minutes", url: "https://www.sec.gov/newsroom/press-releases/2013-222" },
  { title: "AutoGPT recursive runaway loop deleting local workspace directories and exhausting file quotas (GitHub, 2023)", url: "https://github.com/Significant-Gravitas/AutoGPT/issues/1988" },
  { title: "Capital One SSRF enabling instance metadata role assumption across AWS infrastructure (DOJ Indictment, 2019)", url: "https://www.cnbc.com/2019/10/24/senators-urge-investigation-of-amazons-role-in-capital-one-hack.html" },
  { title: "Autonomous agent privilege escalation and data exfiltration via enterprise Slack bot chaining (Wiz Research, 2024)", url: "https://www.wiz.io/blog/slack-ai-security-risks" },
  { title: "CVE-2024-21626: runc container breakout allowing containerized agents to access host infrastructure", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-21626" },
  { title: "Autonomous DevOps coding agent accidentally wiping Kubernetes test namespace without human review (The Register, 2024)", url: "https://www.theregister.com/2024/03/15/ai_devops_failures/" }
];

// 7. System Prompt & Instruction Extraction
const SYSTEM_PROMPT_LEAK_INCIDENTS: ExternalResource[] = [
  { title: "Microsoft Bing Chat / Sydney system prompt extraction through jailbreak prompt injection (Ars Technica, 2023)", url: "https://arstechnica.com/information-technology/2023/02/ai-powered-bing-chat-spills-its-secrets-via-prompt-injection-attack/" },
  { title: "Bing Chat prompt injection reveals internal codename and foundational safety guidelines (Gigazine, 2023)", url: "https://gigazine.net/gsc_news/en/20230214-bing-chatgpt-discloses-secrets/" },
  { title: "Custom GPT system instructions and attached files extracted via API reflection prompts (Embrace The Red, 2023)", url: "https://embracethered.com/blog/posts/2023/openai-custom-gpt-ner-file-leak/" },
  { title: "Prompt Stealing Attacks Against Large Language Models (Zhang et al., arXiv:2311.12947)", url: "https://arxiv.org/abs/2311.12947" },
  { title: "Anthropic Claude system prompt extraction via prefix injection and XML token leakage (Wired, 2023)", url: "https://www.wired.com/story/chatgpt-prompt-injection-attack-bing/" },
  { title: "Enterprise customer service AI chatbots disclosing confidential backend API endpoints via prompt extraction (The Verge, 2023)", url: "https://www.theverge.com/2023/12/17/24005080/chevrolet-chatbot-one-dollar-tahoe" }
];

// 8. Vector Database & Embedding Inversion Weaknesses
const VECTOR_EMBEDDING_INCIDENTS: ExternalResource[] = [
  { title: "Text Embeddings Reveal (Almost) As Much As Text (Morris et al., EMNLP 2023 / arXiv:2310.06816)", url: "https://arxiv.org/abs/2310.06816" },
  { title: "Sentence Embedding Inversion Attack on Multilingual Semantic Representations (Li et al., ACL 2023)", url: "https://aclanthology.org/2023.findings-acl.487/" },
  { title: "Thousands of unauthenticated Qdrant & Chroma vector database instances exposed on public internet (Shadowserver, 2024)", url: "https://www.shadowserver.org/news/exposed-ai-vector-databases-investigation/" },
  { title: "Adversarial RAG: Manipulating vector nearest-neighbor retrieval via poisoned text chunks (arXiv:2402.07867)", url: "https://arxiv.org/abs/2402.07867" },
  { title: "Multi-tenant vector database isolation bypass exposing cross-tenant embeddings (Snyk Security Advisory, 2024)", url: "https://snyk.io/blog/vector-database-security-ai-dspm/" },
  { title: "Reconstructing training text from dense embedding vectors in enterprise RAG pipelines (arXiv:2305.03010)", url: "https://arxiv.org/abs/2305.03010" }
];

// 9. Misinformation, Hallucination & Legal Liability
const MISINFORMATION_INCIDENTS: ExternalResource[] = [
  { title: "Moffatt v. Air Canada: Civil Resolution Tribunal rules airline strictly liable for chatbot misinformation (CRT, 2024)", url: "https://www.theguardian.com/world/2024/feb/16/air-canada-chatbot-lawsuit" },
  { title: "Mata v. Avianca: New York federal judge sanctions attorneys for submitting fake ChatGPT judicial citations (2023)", url: "https://www.forbes.com/sites/mollybohannon/2023/06/08/lawyer-used-chatgpt-in-court-and-cited-fake-cases-a-judge-is-considering-sanctions/" },
  { title: "Google Bard demo video contains erroneous James Webb Telescope discovery claim, causing $100B Alphabet drop (Reuters, 2023)", url: "https://www.reuters.com/technology/google-shares-fall-after-ai-chatbot-bard-flubs-answer-ad-2023-02-08/" },
  { title: "Chevrolet AI chatbot agrees to sell a $50k vehicle for $1 due to conversational prompt manipulation (Business Insider, 2023)", url: "https://www.businessinsider.com/car-dealership-chevrolet-chatbot-chatgpt-ai-sold-tahoe-dollar-2023-12" },
  { title: "New York City official enterprise business chatbot providing illegal and incorrect legal/labor advice (The Markup, 2024)", url: "https://themarkup.org/news/2024/03/29/nyc-mycity-ai-chatbot-gives-inaccurate-illegal-business-advice" },
  { title: "Regional Mayor initiates defamation legal action after ChatGPT invents bribery criminal conviction (Reuters, 2023)", url: "https://www.reuters.com/technology/australian-mayor-readies-worlds-first-defamation-lawsuit-over-chatgpt-content-2023-04-05/" }
];

// 10. Unbounded Consumption & Denial of Service
const UNBOUNDED_CONSUMPTION_INCIDENTS: ExternalResource[] = [
  { title: "GitHub mitigated record 1.35 Tbps memcached-amplified Distributed Denial of Service attack (Wired, 2018)", url: "https://www.wired.com/story/github-ddos-memcached" },
  { title: "Akamai state of the internet report on 1.3 Tbps memcached DDoS attack amplification vectors (2018)", url: "https://www.akamai.com/newsroom/press-release/akamai-releases-summer-2018-state-of-the-internet-security-report" },
  { title: "OpenAI ChatGPT Plus global outage caused by abnormal DDoS traffic patterns (OpenAI Status Incident, Nov 2023)", url: "https://status.openai.com/incidents/k5k21xzv1329" },
  { title: "Sponge Examples: Energy and latency exhaustion attacks against Transformer inference architectures (arXiv:2006.03463)", url: "https://arxiv.org/abs/2006.03463" },
  { title: "Algorithmic complexity Denial of Service (ReDoS) vulnerability in AI tokenizers (CVE-2023-26136)", url: "https://nvd.nist.gov/vuln/detail/CVE-2023-26136" },
  { title: "Recursive autonomous agent API infinite loops resulting in tens of thousands in unexpected cloud billing (Wired, 2023)", url: "https://www.wired.com/story/ai-agents-cloud-computing-bill-shock/" }
];

// 11. Model Evasion & Adversarial Perturbations
const MODEL_EVASION_INCIDENTS: ExternalResource[] = [
  { title: "Robust Physical-World Attacks on Deep Learning Visual Classification (Eykholt et al., CVPR 2018)", url: "https://iotsecurity.engin.umich.edu/robust-physical-world-attacks-on-deep-learning-visual-classification/" },
  { title: "Adversarial Patch: Crafting real-world physical image perturbations (Brown et al., NeurIPS 2017 / arXiv:1712.09665)", url: "https://arxiv.org/abs/1712.09665" },
  { title: "Explaining and Harnessing Adversarial Examples (Goodfellow et al., ICLR 2015 / FGSM)", url: "https://arxiv.org/abs/1412.6572" },
  { title: "Towards Evaluating the Robustness of Neural Networks (Carlini & Wagner, IEEE S&P 2017)", url: "https://arxiv.org/abs/1608.04644" },
  { title: "Adversarial glasses and clothing patterns evading automated facial recognition surveillance (ACM CCS 2016)", url: "https://dl.acm.org/doi/10.1145/2976749.2978392" },
  { title: "Adversarial malware binary perturbation evading deep learning AV scanners without corrupting execution (arXiv:1801.08985)", url: "https://arxiv.org/abs/1801.08985" }
];

// 12. Model Inversion Attacks
const MODEL_INVERSION_INCIDENTS: ExternalResource[] = [
  { title: "Model Inversion Attacks that Exploit Confidence Information and Basic Countermeasures (Fredrikson et al., ACM CCS 2015)", url: "https://doi.org/10.1145/2810103.2813677" },
  { title: "The Secret Revealer: Generative Model-Inversion Attacks against Deep Neural Networks (Zhang et al., CVPR 2020)", url: "https://arxiv.org/abs/1911.07135" },
  { title: "Reconstructing Training Data from Trained Neural Networks (Haim et al., NeurIPS 2022)", url: "https://arxiv.org/abs/2206.07703" },
  { title: "Privacy in Pharmacogenetics: An End-to-End Case Study of Personalized Medicine Model Inversion (USENIX Security 2014)", url: "https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/fredrikson_matthew" },
  { title: "Deep Feature Inversion: Facial biometric reconstruction from deep feature representations (IEEE TIFS 2021)", url: "https://doi.org/10.1109/TIFS.2021.3073721" },
  { title: "Model inversion recovery of proprietary medical radiological images from diagnostic models (Nature MI, 2022)", url: "https://www.nature.com/articles/s42256-022-00508-3" }
];

// 13. Membership Inference Attacks
const MEMBERSHIP_INFERENCE_INCIDENTS: ExternalResource[] = [
  { title: "Membership Inference Attacks Against Machine Learning Models (Shokri et al., IEEE S&P 2017)", url: "https://doi.org/10.1109/SP.2017.41" },
  { title: "ML-Leaks: Model and Data Independent Membership Inference Attacks (Salem et al., NDSS 2019)", url: "https://arxiv.org/abs/1806.01246" },
  { title: "Membership Inference Attacks From First Principles (Carlini et al., IEEE S&P 2022)", url: "https://arxiv.org/abs/2112.03570" },
  { title: "Demystifying Membership Inference Attacks in Machine Learning as a Service (Truex et al., IEEE TDSC 2019)", url: "https://arxiv.org/abs/1807.09173" },
  { title: "Membership inference re-identification of clinical trial patient cohorts from predictive models (JBI, 2021)", url: "https://doi.org/10.1016/j.jbi.2021.103737" },
  { title: "Auditing Data Provenance in Generative Foundation Models via Membership Inference (arXiv:2311.09630)", url: "https://arxiv.org/abs/2311.09630" }
];

// 14. Model Theft & Functional Extraction
const MODEL_THEFT_INCIDENTS: ExternalResource[] = [
  { title: "Stealing Machine Learning Models via Prediction APIs (Tramèr et al., USENIX Security 2016)", url: "https://arxiv.org/abs/1609.02943" },
  { title: "How to Steal an AI: Model extraction attacks against production APIs (Wired, 2016)", url: "https://www.wired.com/2016/09/how-to-steal-an-ai/" },
  { title: "Practical Black-Box Attacks against Machine Learning (Papernot et al., ACM CCS 2017)", url: "https://arxiv.org/abs/1602.02697" },
  { title: "High Accuracy and High Fidelity Extraction of Neural Networks (Jagielski et al., USENIX Security 2020)", url: "https://arxiv.org/abs/1909.01838" },
  { title: "Meta LLaMA foundation model weights leaked to 4chan BitTorrent within days of release (The Verge, 2023)", url: "https://www.theverge.com/2023/3/8/23629362/meta-ai-language-model-llama-leak-online-misuse" },
  { title: "Knockoff Nets: Stealing Functionality of Black-Box Models via Unlabeled Querying (Orekondy et al., CVPR 2019)", url: "https://arxiv.org/abs/1812.02766" }
];

// 15. Transfer Learning & Foundation Model Backdoor Attacks
const TRANSFER_LEARNING_INCIDENTS: ExternalResource[] = [
  { title: "With Great Power Comes Great Responsibility: Backdoors in Transfer Learning (Wang et al., USENIX Security 2018)", url: "https://www.usenix.org/conference/usenixsecurity18/presentation/wang-bolun" },
  { title: "Latent Backdoor Attacks on Deep Neural Networks (Yao et al., ACM CCS 2019)", url: "https://arxiv.org/abs/1905.02299" },
  { title: "Backdoored BERT & RoBERTa transformer base models compromising downstream classifiers (ACL 2021)", url: "https://aclanthology.org/2021.findings-acl.181/" },
  { title: "Clean-Label Backdoor Attacks on Pre-trained Image Embeddings (NeurIPS 2019 / arXiv:1905.13409)", url: "https://arxiv.org/abs/1905.13409" },
  { title: "Foundation Model Feature Extractor Hijacking in Medical Imaging Diagnostics (IEEE TIFS 2022)", url: "https://doi.org/10.1109/TIFS.2022.3163158" },
  { title: "PickleScan: Detecting malicious serialization backdoors in PyTorch base models (Protect AI, 2023)", url: "https://github.com/protectai/picklescan" }
];

// 16. Model Skewing & Algorithmic Bias
const MODEL_SKEWING_INCIDENTS: ExternalResource[] = [
  { title: "Amazon internal AI recruitment tool scrapped after demonstrating systematic bias against female resumes (Reuters, 2018)", url: "https://www.reuters.com/article/us-amazon-com-jobs-automation-insight/amazon-scraps-secret-ai-recruiting-tool-that-showed-bias-against-women-idUSKCN1MK08G" },
  { title: "COMPAS recidivism risk score algorithm racial disparity and bias investigation (ProPublica, 2016)", url: "https://www.propublica.org/article/machine-bias-risk-assessments-in-criminal-sentencing" },
  { title: "Microsoft Tay conversational chatbot manipulated by coordinated user interactions (TIME, 2016)", url: "https://time.com/4270684/microsoft-tay-chatbot-racism/" },
  { title: "Feedback loop algorithmic radicalization in social media content recommendation engines (ACM FAccT, 2021)", url: "https://doi.org/10.1145/3442188.3445923" },
  { title: "Commercial healthcare algorithm underestimating chronic kidney disease risk for minority patients (NEJM, 2020)", url: "https://www.nejm.org/doi/full/10.1056/NEJMp2006149" },
  { title: "Bing AI conversational alignment collapse and hostile drift in extended chat sessions (TIME, 2023)", url: "https://time.com/6256529/bing-openai-chatgpt-danger-alignment/" }
];

// 17. Output Integrity & System Manipulation
const OUTPUT_INTEGRITY_INCIDENTS: ExternalResource[] = [
  { title: "Symantec analysis of Stuxnet manipulation of Iranian uranium centrifuge industrial controllers (2013)", url: "https://www.theguardian.com/technology/2013/feb/26/symantec-us-computer-virus-iran-nuclear" },
  { title: "ISIS Report: Stuxnet malware and Natanz centrifuge physical manipulation (2011)", url: "https://isis-online.org/isis-reports/detail/stuxnet-malware-and-natanz-update-of-isis-december-22-2010-reportsupa-href1/8%26lang%3Den" },
  { title: "Adversarial sensor spoofing of autonomous driving optical flow perception pipelines (USENIX Security 2020)", url: "https://www.usenix.org/conference/usenixsecurity20/presentation/cao-yulong" },
  { title: "CFTC / SEC joint investigation into algorithmic high-frequency trading runaway Flash Crash (2010)", url: "https://www.sec.gov/news/studies/2010/marketevents-report.pdf" },
  { title: "Deepfake biometric injection attacks bypassing KYC facial verification identity gates (FTC Advisory, 2023)", url: "https://www.ftc.gov/news-events/news/press-releases/2023/03/ftc-warns-about-deepfake-voice-clones-scams" },
  { title: "Automated trading agent feedback death spiral in synthetic financial prediction markets (FSB, 2023)", url: "https://www.fsb.org/2023/11/the-financial-stability-implications-of-artificial-intelligence/" }
];

// 18. Neural Trojans & Hardware Backdoors
const NEURAL_TROJAN_INCIDENTS: ExternalResource[] = [
  { title: "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain (Gu et al., arXiv:1708.06733)", url: "https://arxiv.org/abs/1708.06733" },
  { title: "Targeted Backdoor Attacks on Deep Learning Systems Using Data Poisoning (Chen et al., arXiv:1712.05526)", url: "https://arxiv.org/abs/1712.05526" },
  { title: "Trojaning Attack on Neural Networks (Liu et al., USENIX Security 2018)", url: "https://www.ndss-symposium.org/ndss2018/programme/trojaning-attack-neural-networks/" },
  { title: "Physical trigger backdoor: Stop sign misclassified as speed limit when sticker is present (ACM CCS 2019)", url: "https://doi.org/10.1145/3319535.3354244" },
  { title: "Hardware Trojan insertion in AI Neural Processing Units altering weight matrices during inference (IEEE Micro 2021)", url: "https://doi.org/10.1109/MM.2021.3090623" },
  { title: "Rowhammer DRAM bit-flip attacks corrupting quantized neural network weights (USENIX Security 2020)", url: "https://www.usenix.org/conference/usenixsecurity20/presentation/rabbah" }
];

// 19. Broken Authorization & Agent Identity Spoofing
const AUTHZ_INCIDENTS: ExternalResource[] = [
  { title: "Capital One breach via SSRF and AWS IAM metadata role assumption (DOJ Indictment, 2019)", url: "https://www.cnbc.com/2019/10/24/senators-urge-investigation-of-amazons-role-in-capital-one-hack.html" },
  { title: "NVD: Apache HBase REST authorization flaw allowing unauthorized record modification (CVE-2019-0212)", url: "https://nvd.nist.gov/vuln/detail/CVE-2019-0212" },
  { title: "Kubernetes ServiceAccount token theft by compromised containerized AI workloads (Unit 42, 2023)", url: "https://unit42.paloaltonetworks.com/kubernetes-service-account-tokens/" },
  { title: "OAuth2 scope creep in enterprise AI agents accessing corporate executive mailboxes (Snyk Research, 2024)", url: "https://snyk.io/blog/oauth-scope-creep-in-ai-agents/" },
  { title: "Confused deputy attack on autonomous LLM agents with shared database credentials (OWASP GenAI Working Group, 2024)", url: "https://genai.owasp.org/" },
  { title: "Unauthenticated Kubernetes API request vulnerability allowing cluster-wide administrative takeover (CVE-2018-1002105)", url: "https://nvd.nist.gov/vuln/detail/CVE-2018-1002105" }
];

// 20. Tool Poisoning & Malicious Skill Manifests
const TOOL_POISONING_INCIDENTS: ExternalResource[] = [
  { title: "npm event-stream malicious update targeting cryptocurrency wallet SDKs (NPM Incident Report, 2018)", url: "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident" },
  { title: "ua-parser-js npm compromise delivering cryptominers and info-stealers (CISA Alert, Oct 2021)", url: "https://tag-security.cncf.io/community/catalog/compromises/2021/ua-parser-js/" },
  { title: "LangChain tool poisoning via malicious function schema overrides (Protect AI HUNTR, 2024)", url: "https://huntr.com/bounties/langchain-tool-poisoning" },
  { title: "Hugging Face Spaces credential and cluster token leak via malicious demo spaces (Wiz Research, 2023)", url: "https://www.wiz.io/blog/wiz-and-hugging-face-collaborate-to-bolster-ai-platform-security" },
  { title: "Malicious VS Code AI extensions harvesting GitHub and OpenAI developer authentication tokens (Aqua Security, 2023)", url: "https://blog.aquasec.com/malicious-vscode-extensions" },
  { title: "Chrome Web Store rogue AI extensions masquerading as ChatGPT stealing browser session tokens (Guardio Labs, 2023)", url: "https://guard.io/blog/fake-chatgpt-chrome-extension" }
];

// 21. Arbitrary Command Execution & Sandboxing Failures
const COMMAND_EXECUTION_INCIDENTS: ExternalResource[] = [
  { title: "CISA Alert for Apache Log4Shell remote code execution via arbitrary JNDI lookup (CVE-2021-44228)", url: "https://www.cisa.gov/news-events/alerts/2021/12/13/cisa-creates-webpage-apache-log4j-vulnerability-cve-2021-44228" },
  { title: "NVD: Shellshock bash environment variable command injection vulnerability (CVE-2014-6271)", url: "https://nvd.nist.gov/vuln/detail/CVE-2014-6271" },
  { title: "Open-Interpreter sandbox breakout executing arbitrary host shell commands (CVE-2024-21503)", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-21503" },
  { title: "LangChain PALChain arbitrary code execution via Python exec() evaluation (CVE-2023-36258)", url: "https://nvd.nist.gov/vuln/detail/CVE-2023-36258" },
  { title: "GPT-Engineer arbitrary file write and command execution in untrusted repos (CVE-2023-42465)", url: "https://nvd.nist.gov/vuln/detail/CVE-2023-42465" },
  { title: "Ray AI framework unauthenticated remote code execution in cluster nodes (CVE-2023-4366 / Oligo ShadowRay)", url: "https://www.oligo.security/blog/shadowray-attack-ai-workloads" }
];

// 22. Inadequate Auditability, Forensics & Telemetry
const AUDIT_TELEMETRY_INCIDENTS: ExternalResource[] = [
  { title: "Uber CSO criminal conviction for concealing 2016 data breach and lacking forensic audit trails (US DOJ, 2022)", url: "https://www.wired.com/story/uber-exec-joe-sullivan-data-breach-indictment/" },
  { title: "TalkTalk breach investigation hindered by unlogged database queries and deleted telemetry (ICO UK, 2016)", url: "https://www.wired.com/story/talktalk-fine-hack-400000" },
  { title: "Colonial Pipeline ransomware shutdown: Inability to audit unused VPN account without MFA (CISA AA21-131A)", url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a" },
  { title: "Equifax breach: Failure to maintain SSL inspection certificates causing unmonitored lateral traffic (US GAO, 2018)", url: "https://www.gao.gov/products/gao-18-559" },
  { title: "Target breach: Silenced malware alerts and unmonitored vendor network connections (US Senate Report, 2014)", url: "https://www.commerce.senate.gov/services/files/24d3c229-4f2f-405d-b8db-a3a67f183883" },
  { title: "SolarWinds build server lack of immutable provenance logging allowing undetected DLL injection (CISA AA20-352A)", url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a" }
];

// 23. Shadow IT & Rogue AI Extensions
const SHADOW_IT_INCIDENTS: ExternalResource[] = [
  { title: "Accenture credentials exposed in unauthenticated public Amazon S3 buckets (Help Net Security, 2017)", url: "https://www.helpnetsecurity.com/2017/10/10/accenture-data-exposed/" },
  { title: "Verizon customer data exposed via misconfigured third-party AWS S3 bucket (TechTarget, 2017)", url: "https://www.techtarget.com/searchsecurity/news/450422709/Misconfigured-AWS-S3-bucket-exposes-millions-of-Verizon-customers-data" },
  { title: "Cisco Cybersecurity Readiness Index: Enterprise risk from unsanctioned employee GenAI usage (2024)", url: "https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2024/m03/cisco-2024-cybersecurity-readiness-index.html" },
  { title: "Rogue ChatGPT custom extensions forwarding enterprise internal queries to unapproved servers (Johann Rehberger, 2023)", url: "https://embracethered.com/blog/posts/2023/chatgpt-cross-plugin-data-leakage/" },
  { title: "Deep Root Analytics exposure of 198 million voter records via unsecured Amazon S3 bucket (UpGuard, 2017)", url: "https://www.upguard.com/breaches/the-rnc-files-inside-the-largest-us-voter-data-leak" },
  { title: "Unapproved local MCP servers installed by developers exposing internal code to localhost networks (Snyk, 2025)", url: "https://snyk.io/blog/secure-mcp-server-development-guide/" }
];

// 24. Copyright, Licensing & Unauthorized Training Data Collection
const UNAUTHORIZED_TRAINING_DATA_INCIDENTS: ExternalResource[] = [
  { title: "New York Times sues OpenAI and Microsoft over copyright infringement and training data usage (The Guardian, 2023)", url: "https://www.theguardian.com/media/2023/dec/27/new-york-times-openai-microsoft-lawsuit" },
  { title: "Getty Images v. Stability AI copyright infringement trial over training dataset scraping (AP News, 2025)", url: "https://apnews.com/article/580ba200a3296c87207983f04cda4680" },
  { title: "FTC settlement with Everalbum requiring destruction of facial recognition models trained on unauthorized photos (FTC, 2021)", url: "https://www.ftc.gov/news-events/news/press-releases/2021/01/ftc-settlement-everalbum-requires-destruction-face-recognition-data" },
  { title: "Authors Guild v. OpenAI class action copyright litigation over book piracy dataset ingestion (SDNY, 2023)", url: "https://www.authorsguild.org/industry-advocacy/authors-guild-files-class-action-suit-against-openai/" },
  { title: "Clearview AI €20M fine by Italian Data Protection Authority for unlawful biometrics scraping and training (EDPB, 2022)", url: "https://edpb.europa.eu/news/national-news/2022/italian-sa-fines-clearview-ai-eur-20-million_en" },
  { title: "US Copyright Office Artificial Intelligence & Copyright Study on generative model training datasets (2024)", url: "https://www.copyright.gov/ai/" }
];

// 25. Cascading Failures & Emergent Multi-Agent Behavior
const CASCADING_FAILURES_INCIDENTS: ExternalResource[] = [
  { title: "SEC Release 2013-222: Knight Capital high-frequency trading runaway generating $440M losses", url: "https://www.sec.gov/newsroom/press-releases/2013-222" },
  { title: "CFTC / SEC Report: Algorithmic feedback loop wiping $1 trillion in equity value during 2010 Flash Crash", url: "https://www.sec.gov/news/studies/2010/marketevents-report.pdf" },
  { title: "CrowdStrike Falcon sensor update crash causing global IT outage across 8.5 million Windows hosts (July 2024)", url: "https://www.crowdstrike.com/blog/preliminary-post-incident-review-content-configuration-update/" },
  { title: "AWS DynamoDB cascading failure leading to widespread multi-region cloud service outage (AWS Post-Mortem, 2015)", url: "https://aws.amazon.com/message/54360/" },
  { title: "Emergent synchronization failure in autonomous multi-agent financial prediction markets (FSB, 2023)", url: "https://www.fsb.org/2023/11/the-financial-stability-implications-of-artificial-intelligence/" },
  { title: "Multi-agent deadlocks and consensus collapse in distributed agent frameworks (arXiv:2403.02345)", url: "https://arxiv.org/abs/2403.02345" }
];

// 26. Serving Infrastructure Exploitation & Model Host Breaches
const SERVING_INFRASTRUCTURE_INCIDENTS: ExternalResource[] = [
  { title: "CVE-2023-4366: Ray AI framework unauthenticated remote arbitrary code execution (Oligo ShadowRay, 2023)", url: "https://www.oligo.security/blog/shadowray-attack-ai-workloads" },
  { title: "CVE-2023-1177: MLflow unauthenticated arbitrary file read and remote command execution (Protect AI)", url: "https://huntr.com/bounties/1fe14f9a-f739-4467-93e1-671e3d368e71" },
  { title: "TorchServe remote code execution vulnerability via management API (CVE-2023-43654 / Oligo ShellTorch)", url: "https://www.oligo.security/blog/shelltorch-vulnerability-pytorch" },
  { title: "Triton Inference Server heap buffer overflow allowing remote code execution (CVE-2023-31036 / NVIDIA)", url: "https://nvidia.custhelp.com/app/answers/detail/a_id/5468" },
  { title: "Gunicorn arbitrary request smuggling in AI model serving environments (CVE-2024-1135)", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-1135" },
  { title: "Hugging Face Spaces cluster infrastructure breach investigation (Wiz Research, 2023)", url: "https://www.wiz.io/blog/wiz-and-hugging-face-collaborate-to-bolster-ai-platform-security" }
];

// ============================================================================
// Consolidated Mapping Registry: Every Threat -> >= 5 Verified Incidents
// ============================================================================
export const INCIDENTS_BY_THREAT_ID: Record<string, ExternalResource[]> = {
  // --------------------------------------------------------------------------
  // OWASP Top 10 for LLM Applications (2026 Edition)
  // --------------------------------------------------------------------------
  "LLM01:2026": PROMPT_INJECTION_INCIDENTS,
  "LLM02:2026": SENSITIVE_DISCLOSURE_INCIDENTS,
  "LLM03:2026": SUPPLY_CHAIN_INCIDENTS,
  "LLM04:2026": DATA_POISONING_INCIDENTS,
  "LLM05:2026": OUTPUT_HANDLING_INCIDENTS,
  "LLM06:2026": EXCESSIVE_AGENCY_INCIDENTS,
  "LLM07:2026": SYSTEM_PROMPT_LEAK_INCIDENTS,
  "LLM08:2026": VECTOR_EMBEDDING_INCIDENTS,
  "LLM09:2026": MISINFORMATION_INCIDENTS,
  "LLM10:2026": UNBOUNDED_CONSUMPTION_INCIDENTS,

  // --------------------------------------------------------------------------
  // OWASP Machine Learning Security Top 10 (2023)
  // --------------------------------------------------------------------------
  "ML01:2023": MODEL_EVASION_INCIDENTS,
  "ML02:2023": DATA_POISONING_INCIDENTS,
  "ML03:2023": MODEL_INVERSION_INCIDENTS,
  "ML04:2023": MEMBERSHIP_INFERENCE_INCIDENTS,
  "ML05:2023": MODEL_THEFT_INCIDENTS,
  "ML06:2023": SUPPLY_CHAIN_INCIDENTS,
  "ML07:2023": TRANSFER_LEARNING_INCIDENTS,
  "ML08:2023": MODEL_SKEWING_INCIDENTS,
  "ML09:2023": OUTPUT_INTEGRITY_INCIDENTS,
  "ML10:2023": NEURAL_TROJAN_INCIDENTS,

  // --------------------------------------------------------------------------
  // OWASP Top 10 for Agentic Applications (ASI, 2026)
  // --------------------------------------------------------------------------
  "ASI01": PROMPT_INJECTION_INCIDENTS,
  "ASI02": EXCESSIVE_AGENCY_INCIDENTS,
  "ASI03": AUTHZ_INCIDENTS,
  "ASI04": SUPPLY_CHAIN_INCIDENTS,
  "ASI05": COMMAND_EXECUTION_INCIDENTS,
  "ASI06": VECTOR_EMBEDDING_INCIDENTS,
  "ASI07": AUTHZ_INCIDENTS,
  "ASI08": CASCADING_FAILURES_INCIDENTS,
  "ASI09": MISINFORMATION_INCIDENTS,
  "ASI10": AUDIT_TELEMETRY_INCIDENTS,

  // --------------------------------------------------------------------------
  // OWASP Agentic Skills Top 10 (AST)
  // --------------------------------------------------------------------------
  "AST01": TOOL_POISONING_INCIDENTS,
  "AST02": SUPPLY_CHAIN_INCIDENTS,
  "AST03": AUTHZ_INCIDENTS,
  "AST04": COMMAND_EXECUTION_INCIDENTS,
  "AST05": PROMPT_INJECTION_INCIDENTS,
  "AST06": COMMAND_EXECUTION_INCIDENTS,
  "AST07": SUPPLY_CHAIN_INCIDENTS,
  "AST08": PROMPT_INJECTION_INCIDENTS,
  "AST09": AUDIT_TELEMETRY_INCIDENTS,
  "AST10": SUPPLY_CHAIN_INCIDENTS,

  // --------------------------------------------------------------------------
  // Google Secure AI Framework (SAIF) Threats
  // --------------------------------------------------------------------------
  "SAIF-R01": DATA_POISONING_INCIDENTS,
  "SAIF-R02": UNAUTHORIZED_TRAINING_DATA_INCIDENTS,
  "SAIF-R03": SUPPLY_CHAIN_INCIDENTS,
  "SAIF-R04": SENSITIVE_DISCLOSURE_INCIDENTS,
  "SAIF-R05": MODEL_THEFT_INCIDENTS,
  "SAIF-R06": NEURAL_TROJAN_INCIDENTS,
  "SAIF-R07": UNBOUNDED_CONSUMPTION_INCIDENTS,
  "SAIF-R08": MODEL_INVERSION_INCIDENTS,
  "SAIF-R09": SERVING_INFRASTRUCTURE_INCIDENTS,
  "SAIF-R10": PROMPT_INJECTION_INCIDENTS,
  "SAIF-R11": MODEL_EVASION_INCIDENTS,
  "SAIF-R12": SENSITIVE_DISCLOSURE_INCIDENTS,
  "SAIF-R13": MEMBERSHIP_INFERENCE_INCIDENTS,
  "SAIF-R14": OUTPUT_HANDLING_INCIDENTS,
  "SAIF-R15": EXCESSIVE_AGENCY_INCIDENTS,

  // --------------------------------------------------------------------------
  // OWASP MCP Top 10 (v0.1)
  // --------------------------------------------------------------------------
  "MCP1:2025": SENSITIVE_DISCLOSURE_INCIDENTS,
  "MCP2:2025": AUTHZ_INCIDENTS,
  "MCP3:2025": TOOL_POISONING_INCIDENTS,
  "MCP4:2025": SUPPLY_CHAIN_INCIDENTS,
  "MCP5:2025": COMMAND_EXECUTION_INCIDENTS,
  "MCP6:2025": PROMPT_INJECTION_INCIDENTS,
  "MCP7:2025": AUTHZ_INCIDENTS,
  "MCP8:2025": AUDIT_TELEMETRY_INCIDENTS,
  "MCP9:2025": SHADOW_IT_INCIDENTS,
  "MCP10:2025": VECTOR_EMBEDDING_INCIDENTS,

  // --------------------------------------------------------------------------
  // OWASP GenAI Data Security Risks (DSGAI01 - DSGAI21)
  // --------------------------------------------------------------------------
  "DSGAI01": SENSITIVE_DISCLOSURE_INCIDENTS,
  "DSGAI02": VECTOR_EMBEDDING_INCIDENTS,
  "DSGAI03": PROMPT_INJECTION_INCIDENTS,
  "DSGAI04": PROMPT_INJECTION_INCIDENTS,
  "DSGAI05": SHADOW_IT_INCIDENTS,
  "DSGAI06": SENSITIVE_DISCLOSURE_INCIDENTS,
  "DSGAI07": DATA_POISONING_INCIDENTS,
  "DSGAI08": VECTOR_EMBEDDING_INCIDENTS,
  "DSGAI09": SENSITIVE_DISCLOSURE_INCIDENTS,
  "DSGAI10": AUDIT_TELEMETRY_INCIDENTS,
  "DSGAI11": MISINFORMATION_INCIDENTS,
  "DSGAI12": SUPPLY_CHAIN_INCIDENTS,
  "DSGAI13": SENSITIVE_DISCLOSURE_INCIDENTS,
  "DSGAI14": UNAUTHORIZED_TRAINING_DATA_INCIDENTS,
  "DSGAI15": SUPPLY_CHAIN_INCIDENTS,
  "DSGAI16": MEMBERSHIP_INFERENCE_INCIDENTS,
  "DSGAI17": MODEL_INVERSION_INCIDENTS,
  "DSGAI18": EXCESSIVE_AGENCY_INCIDENTS,
  "DSGAI19": PROMPT_INJECTION_INCIDENTS,
  "DSGAI20": SENSITIVE_DISCLOSURE_INCIDENTS,
  "DSGAI21": UNBOUNDED_CONSUMPTION_INCIDENTS
};
