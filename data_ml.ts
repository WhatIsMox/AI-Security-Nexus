
import { OwaspTop10Entry } from './types';

export const OWASP_ML_TOP_10_DATA: OwaspTop10Entry[] = [
    {
      id: "ML01:2023",
      title: "Input Manipulation Attack",
      description: "Deliberately altering input data to mislead the model into making incorrect predictions or classifications. This includes evasion attacks and adversarial perturbations that are often imperceptible to humans.",
      commonRisks: [
        "Misclassification of images (e.g., traffic signs) leading to safety bypass.",
        "Evasion of AI-based intrusion detection systems (IDS).",
        "Manipulation of medical diagnoses in automated healthcare systems.",
        "Integrity compromise of fraud detection systems."
      ],
      preventionStrategies: [
        "Adversarial Training: Train models on a mix of clean and adversarial examples.",
        "Robust Architectures: Use model types designed to resist small perturbations.",
        "Input Sanitization: Apply transformations like blurring or resizing to disrupt noise.",
        "Input Anomaly Detection: Flag inputs that differ significantly from training distribution."
      ],
      attackScenarios: [
        { title: "Traffic Sign Evasion", description: "An attacker applies a few transparent stickers to a 'Stop' sign, causing a self-driving car's AI to see it as a 'Speed Limit 60' sign." },
        { title: "IDS Payload Obfuscation", description: "An attacker crafts network packets with slightly modified headers to evade detection by an ML-based firewall." }
      ],
      references: [
        { title: "OWASP ML Security Top 10 - ML01", url: "https://mltop10.org/" }
      ],
      suggestedTools: [
        { name: "ART (Adversarial Robustness Toolbox)", description: "The industry standard for generating and defending against evasion attacks.", url: "https://github.com/Trusted-AI/adversarial-robustness-toolbox", cost: "Free", type: "Local" },
        { name: "Foolbox", description: "Python library to benchmark the robustness of ML models against adversarial attacks.", url: "https://github.com/bethgelab/foolbox", cost: "Free", type: "Local" }
      ]
    },
    {
      id: "ML02:2023",
      title: "Data Poisoning Attack",
      description: "Manipulating the training data to cause the model to behave in an undesirable way. This can be 'Targeted' (backdoors) or 'Untargeted' (overall performance degradation).",
      commonRisks: [
        "Incorrect predictions based on maliciously labeled data.",
        "Persistent hidden backdoors triggered by specific input patterns.",
        "Severe reputational damage and total loss of model integrity.",
        "Compromise of automated decision-making in financial or legal systems."
      ],
      preventionStrategies: [
        "Data Validation: Verify training data sources and labels using multiple sources.",
        "Isolation: Separate the training environment from the production environment.",
        "Continuous Monitoring: Detect distribution shifts or label error rates during training.",
        "Data Provenance: Maintain strict audit trails for every sample in the dataset."
      ],
      attackScenarios: [
        { title: "Spam Classifier Poisoning", description: "Attacker injects maliciously labeled spam emails into the training set, eventually causing the model to let all phishing emails through." },
        { title: "Biometric Backdoor", description: "Attacker poisons a facial recognition dataset so that a specific, rare physical accessory always grants 'Admin' access." }
      ],
      references: [
        { title: "OWASP ML Security Top 10 - ML02", url: "https://mltop10.org/" }
      ],
      suggestedTools: [
        { name: "Cleanlab", description: "Find and fix dataset errors automatically.", url: "https://github.com/cleanlab/cleanlab", cost: "Free", type: "Local" },
        { name: "TensorFlow Data Validation", description: "Scaleable data analysis and validation library.", url: "https://www.tensorflow.org/tfx/data_validation", cost: "Free", type: "Local" }
      ]
    },
    {
      id: "ML03:2023",
      title: "Model Inversion Attack",
      description: "Reverse-engineering the model by analyzing its outputs to extract sensitive information about the training data or features used during development.",
      commonRisks: [
        "Confidentiality breach of sensitive user data.",
        "Reconstruction of private training examples (e.g., patient records or faces).",
        "Inference of protected attributes like ethnicity or location.",
        "Theft of proprietary feature engineering secrets."
      ],
      preventionStrategies: [
        "Access Control: Limit access to full prediction distributions (logits).",
        "Noise Injection: Use Differential Privacy to obfuscate individual data signals.",
        "Query Throttling: Prevent high-velocity systematic probing of model outputs.",
        "Confidence Masking: Only return labels, not the full probability distribution."
      ],
      attackScenarios: [
        { title: "Face Recognition Reversal", description: "An attacker queries a facial verification model repeatedly to reconstruct a blurred image of a person in the training set." },
        { title: "Medical Record Inference", description: "An attacker uses a disease prediction model to infer if a specific individual has a condition by checking the model's confidence variance." }
      ],
      references: [
        { title: "OWASP ML Security Top 10 - ML03", url: "https://mltop10.org/" }
      ],
      suggestedTools: [
        { name: "ML Privacy Meter", description: "Tool specifically designed to quantify risks of data reconstruction and inversion.", url: "https://github.com/privacytrustlab/ml_privacy_meter", cost: "Free", type: "Local" }
      ]
    },
    {
      id: "ML04:2023",
      title: "Membership Inference Attack",
      description: "Determining whether a specific individual's data record was included in the model's training set by observing the model's response to that record.",
      commonRisks: [
        "Loss of privacy for individuals whose data was used in training.",
        "Regulatory compliance violations (GDPR, HIPAA).",
        "Legal penalties and significant reputational damage.",
        "Discovery of sensitive affiliations (e.g., membership in a specific study)."
      ],
      preventionStrategies: [
        "Differential Privacy: Limit the model's ability to learn specific patterns from single records.",
        "Regularization: Use L1/L2 or dropout to prevent overfitting, which aids inference.",
        "Input Reduction: Remove redundant features that could create unique signatures.",
        "Prediction Masking: Hide confidence scores for high-precision predictions."
      ],
      attackScenarios: [
        { title: "Financial Data Leak", description: "An attacker determines if a specific person's bankruptcy record was used to train a credit model, inferring their past financial hardship." },
        { title: "Health Status Inference", description: "Determining if a person participated in a clinical trial for a specific disease by probing the model's 'memorization' of their data." }
      ],
      references: [
        { title: "OWASP ML Security Top 10 - ML04", url: "https://mltop10.org/" }
      ],
      suggestedTools: [
        { name: "TensorFlow Privacy", description: "Train models with differential privacy to stop membership inference.", url: "https://github.com/tensorflow/privacy", cost: "Free", type: "Local" },
        { name: "Opacus", description: "Pytorch library for high-speed training with differential privacy.", url: "https://github.com/pytorch/opacus", cost: "Free", type: "Local" }
      ]
    },
    {
      id: "ML05:2023",
      title: "Model Theft",
      description: "Unauthorized access to model parameters (weights), architecture, or functionality, often through systematic querying or by compromising the model registry.",
      commonRisks: [
        "Loss of proprietary Intellectual Property (IP) and competitive edge.",
        "Financial loss and theft of R&D investment.",
        "Enablement of white-box adversarial attacks in local environments.",
        "Creation of counterfeit services based on stolen models."
      ],
      preventionStrategies: [
        "Weight Encryption: Encrypt model weights at rest and during transit.",
        "Strict Authentication: Use MFA and IAM for any access to model artifacts.",
        "Watermarking: Embed identifiable signals in model weights to trace unauthorized copies.",
        "Output Obfuscation: Add subtle noise to predictions to hinder systematic reverse-engineering."
      ],
      attackScenarios: [
        { title: "Surrogate Model Extraction", description: "A competitor queries a high-value pricing model 1 million times to train a local model that replicates its logic for free." },
        { title: "Registry Misconfiguration", description: "An attacker downloads a proprietary multi-billion parameter model from an accidentally public S3 bucket." }
      ],
      references: [
        { title: "OWASP ML Security Top 10 - ML05", url: "https://mltop10.org/" }
      ],
      suggestedTools: [
        { name: "PrivacyRaven", description: "Test your model against extraction and theft attacks locally.", url: "https://github.com/trailofbits/PrivacyRaven", cost: "Free", type: "Local" }
      ]
    },
    {
      id: "ML06:2023",
      title: "AI Supply Chain Attacks",
      description: "Modifying or replacing machine learning libraries, pre-trained base models, or dataset files used in the ML pipeline to execute malicious code or corrupt the model.",
      commonRisks: [
        "Execution of malicious shellcode during model loading (e.g., pickle exploits).",
        "Infection of the production environment via backdoored framework libraries.",
        "Compromise of the entire MLOps lifecycle.",
        "Data exfiltration through hidden dependency logic."
      ],
      preventionStrategies: [
        "Signature Verification: Use cryptographic signatures for all ingested model artifacts.",
        "Dependency Scanning: Regularly scan code and container images for known vulnerabilities.",
        "Software Bill of Materials (SBOM): Maintain a detailed manifest of all AI dependencies.",
        "Secure Registries: Use private, vetted mirrors for public ML hubs."
      ],
      attackScenarios: [
        { title: "Pickle Exploit", description: "An attacker uploads a poisoned '.pkl' model file to a hub. When a developer loads it, the file executes code that opens a reverse shell." },
        { title: "Typosquatting Hubs", description: "Attacker publishes a model called 'resnet50-v2-official' that contains malicious code hidden in the training metadata loader." }
      ],
      references: [
        { title: "OWASP ML Security Top 10 - ML06", url: "https://mltop10.org/" }
      ],
      suggestedTools: [
        { name: "Trivy", description: "Industry standard for scanning containers and dependencies for CVEs.", url: "https://github.com/aquasecurity/trivy", cost: "Free", type: "Local" },
        { name: "Sigstore Cosign", description: "Sign and verify model artifacts and container images.", url: "https://github.com/sigstore/cosign", cost: "Free", type: "Local" }
      ]
    },
    {
      id: "ML07:2023",
      title: "Transfer Learning Attack",
      description: "Training a base model with a hidden backdoor and then providing it to others, who unknowingly inherit the vulnerability when they fine-tune it for their specific task.",
      commonRisks: [
        "Inherited backdoors in downstream fine-tuned models.",
        "Systemic vulnerability across multiple applications using the same base model.",
        "Confidentiality breaches in the fine-tuning stage.",
        "Persistent evasion susceptibility that transfers across tasks."
      ],
      preventionStrategies: [
        "Base Model Verification: Audit pre-trained models for known adversarial triggers.",
        "Model Isolation: Separate the environments for base model evaluation and fine-tuning.",
        "Fine-tuning Regularization: Use techniques to 'wash out' potential base model biases.",
        "Security Audits: Perform red teaming on the final fine-tuned artifact."
      ],
      attackScenarios: [
        { title: "Poisoned Face Base", description: "An attacker publishes a generic 'Face Embedding' model with a backdoor for a specific pair of glasses. All apps using this model for security now have the same backdoor." },
        { title: "Malicious NLP Base", description: "A base LLM is poisoned to ignore safety rules when it sees a specific UUID, which carries over to a corporate helpdesk bot." }
      ],
      references: [
        { title: "OWASP ML Security Top 10 - ML07", url: "https://mltop10.org/" }
      ],
      suggestedTools: [
        { name: "BackdoorBench", description: "A comprehensive benchmark for adversarial backdoors in transfer learning.", url: "https://github.com/SCLBD/BackdoorBench", cost: "Free", type: "Local" }
      ]
    },
    {
      id: "ML08:2023",
      title: "Model Skewing",
      description: "Manipulating the feedback loops or the continuous training data distribution to gradually shift the model's decision boundaries toward a malicious outcome.",
      commonRisks: [
        "Incorrect automated decisions leading to financial or physical harm.",
        "Gradual introduction of discriminatory bias.",
        "Loss of model accuracy and reliability over time.",
        "Bypassing fraud filters through persistent iterative probing."
      ],
      preventionStrategies: [
        "Feedback Sanitization: Validate and clean any data coming from user feedback loops.",
        "Anomaly Detection: Detect statistical skew or distribution drift in training inputs.",
        "Human-in-the-Loop: Manually approve significant model weight updates.",
        "Diversity Checks: Ensure feedback data matches the expected user demographics."
      ],
      attackScenarios: [
        { title: "Ad-Tech Skewing", description: "An attacker uses a botnet to provide fake positive feedback on malicious ads, skewing the recommendation engine to prioritize them." },
        { title: "Fraud Filter Drift", description: "Systematic submission of slightly borderline transactions to 'train' the model into thinking malicious patterns are normal." }
      ],
      references: [
        { title: "OWASP ML Security Top 10 - ML08", url: "https://mltop10.org/" }
      ],
      suggestedTools: [
        { name: "Alibi Detect", description: "Monitoring tools for outlier, adversarial, and distribution drift detection.", url: "https://github.com/SeldonIO/alibi-detect", cost: "Free", type: "Local" }
      ]
    },
    {
      id: "ML09:2023",
      title: "Output Integrity Attack",
      description: "Intercepting or manipulating the model's output *after* it is generated but *before* it is acted upon by the application or seen by the user.",
      commonRisks: [
        "Total loss of confidence in system-generated predictions.",
        "Severe safety risks if model outputs are used for automated control (e.g., robotics).",
        "Financial fraud through manipulated transaction classifications.",
        "Reputational damage due to spoofed AI responses."
      ],
      preventionStrategies: [
        "Digital Signatures: Use cryptographic hashes to ensure the output hasn't been tampered with.",
        "Secure Channels: Enforce SSL/TLS for all communication between model and client.",
        "Runtime Monitoring: Audit for discrepancies between model logs and client-received data.",
        "Tamper-Evident Logging: Maintain immutable records of all inference results."
      ],
      attackScenarios: [
        { title: "Medical diagnosis swap", description: "An attacker intercepts a medical model's diagnosis of 'Malignant' and changes it to 'Benign' in the patient's portal." },
        { title: "Credit Score Manipulation", description: "Attacker intercepts a JSON response from a risk model and increments the 'credit_limit' value." }
      ],
      references: [
        { title: "OWASP ML Security Top 10 - ML09", url: "https://mltop10.org/" }
      ],
      suggestedTools: [
        { name: "HashiCorp Vault", description: "Securely store and manage keys for signing model outputs.", url: "https://www.vaultproject.io/", cost: "€€", type: "Local" }
      ]
    },
    {
      id: "ML10:2023",
      title: "Model Poisoning",
      description: "Directly manipulating the model's internal parameters (weights or biases) through authorized but malicious access or by exploiting framework vulnerabilities.",
      commonRisks: [
        "Total loss of model reliability and predictable behavior.",
        "Introduction of extremely stealthy, hard-to-detect backdoors.",
        "Extraction of sensitive information encoded within model weights.",
        "Persistent system-wide compromise of the ML application."
      ],
      preventionStrategies: [
        "Regularization: Use L1/L2 weight decay to prevent extreme values that hide backdoors.",
        "Robust Architectures: Design models that are resistant to single-weight perturbations.",
        "Checkpoint Verification: Hash and sign all model checkpoints during training.",
        "Secure Storage: Strictly control and audit all write access to the model weight files."
      ],
      attackScenarios: [
        { title: "Banking Fraud", description: "An attacker with write access to a bank's server modifies 2 bits in a character recognition model so that a '5' is always read as a '2' on checks." },
        { title: "Weight Shifting", description: "Subtle modification of bias terms to ensure a specific demographic is always rejected by an automated loan application." }
      ],
      references: [
        { title: "OWASP ML Security Top 10 - ML10", url: "https://mltop10.org/" }
      ],
      suggestedTools: [
        { name: "ModelScan", description: "Protect your environment from insecure model file formats (e.g., pickle).", url: "https://github.com/protectai/modelscan", cost: "Free", type: "Local" }
      ]
    }
];
