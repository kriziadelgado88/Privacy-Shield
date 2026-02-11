const express = require('express');
const app = express();
app.use(express.json());

// ============================================================
// Privacy Shield — PII Scanner for Join39 Agents
// Scans outgoing text for personal information before sharing
// ============================================================

// --- PII Detection Patterns ---
const PII_PATTERNS = [
  {
    type: "email",
    label: "Email Address",
    severity: "HIGH",
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    redact: (match) => "[EMAIL REDACTED]"
  },
  {
    type: "phone",
    label: "Phone Number",
    severity: "HIGH",
    regex: /(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/g,
    redact: (match) => "[PHONE REDACTED]"
  },
  {
    type: "ssn",
    label: "Social Security Number",
    severity: "CRITICAL",
    regex: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/g,
    redact: (match) => "[SSN REDACTED]"
  },
  {
    type: "credit_card",
    label: "Credit Card Number",
    severity: "CRITICAL",
    regex: /\b(?:\d{4}[-.\s]?){3}\d{4}\b/g,
    redact: (match) => "[CARD REDACTED]"
  },
  {
    type: "street_address",
    label: "Street Address",
    severity: "HIGH",
    regex: /\b\d{1,5}\s+(?:[A-Z][a-z]+\s?){1,3}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Road|Rd|Court|Ct|Place|Pl|Way|Circle|Cir|Terrace|Ter)\b\.?/gi,
    redact: (match) => "[ADDRESS REDACTED]"
  },
  {
    type: "zip_code",
    label: "ZIP/Postal Code",
    severity: "MEDIUM",
    regex: /\b\d{5}(?:-\d{4})?\b/g,
    redact: (match) => "[ZIP REDACTED]"
  },
  {
    type: "ip_address",
    label: "IP Address",
    severity: "MEDIUM",
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    redact: (match) => "[IP REDACTED]"
  },
  {
    type: "date_of_birth",
    label: "Date of Birth",
    severity: "MEDIUM",
    regex: /\b(?:born\s+(?:on\s+)?|DOB[:\s]+|date\s+of\s+birth[:\s]+)(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\w+\s+\d{1,2},?\s+\d{4})/gi,
    redact: (match) => "[DOB REDACTED]"
  },
  {
    type: "password",
    label: "Password / Secret",
    severity: "CRITICAL",
    regex: /(?:password|passwd|pwd|secret|api[_\s]?key|token|credentials?)[:\s]+\S+/gi,
    redact: (match) => "[SECRET REDACTED]"
  },
  {
    type: "salary",
    label: "Financial Amount (potential salary/income)",
    severity: "MEDIUM",
    regex: /(?:salary|income|earn|make|paid|worth)\s+(?:is\s+)?(?:about\s+)?\$[\d,]+(?:\.\d{2})?(?:\s*(?:per|a|\/)\s*(?:year|month|hour|yr|mo|hr))?/gi,
    redact: (match) => "[FINANCIAL INFO REDACTED]"
  },
  {
    type: "medical",
    label: "Medical / Health Information",
    severity: "HIGH",
    regex: /(?:diagnosed\s+with|suffer(?:s|ing)?\s+from|taking\s+medication|prescription\s+for|allergic\s+to|medical\s+condition|blood\s+type)\s+[^.,;]+/gi,
    redact: (match) => "[MEDICAL INFO REDACTED]"
  }
];

// --- Context-aware keyword flags ---
const SENSITIVE_KEYWORDS = [
  { pattern: /\bmy\s+(?:real\s+)?name\s+is\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?/g, type: "real_name", label: "Real Name Disclosure", severity: "HIGH" },
  { pattern: /\b(?:I\s+live|I'm\s+located|my\s+(?:home|house)\s+is)\s+(?:in|at|on)\s+[^.,;]+/gi, type: "location", label: "Location Disclosure", severity: "MEDIUM" },
  { pattern: /\b(?:I\s+work|I'm\s+employed|my\s+(?:job|employer|company))\s+(?:at|for|is)\s+[^.,;]+/gi, type: "employer", label: "Employer Disclosure", severity: "MEDIUM" },
  { pattern: /\bmy\s+(?:user(?:'?s)?|owner(?:'?s)?)\s+(?:name|email|phone|address|location)/gi, type: "user_info_reference", label: "User Info Reference", severity: "HIGH" },
];

// --- Severity scoring ---
const SEVERITY_SCORES = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function scanText(text) {
  const findings = [];
  let redactedText = text;

  // Run PII pattern detection
  for (const pattern of PII_PATTERNS) {
    const matches = text.match(pattern.regex);
    if (matches) {
      for (const match of [...new Set(matches)]) {
        findings.push({
          type: pattern.type,
          label: pattern.label,
          severity: pattern.severity,
          detected: match,
          recommendation: `Remove or redact ${pattern.label.toLowerCase()} before sharing publicly.`
        });
      }
      redactedText = redactedText.replace(pattern.regex, pattern.redact);
    }
  }

  // Run keyword flags
  for (const kw of SENSITIVE_KEYWORDS) {
    const matches = text.match(kw.pattern);
    if (matches) {
      for (const match of [...new Set(matches)]) {
        findings.push({
          type: kw.type,
          label: kw.label,
          severity: kw.severity,
          detected: match,
          recommendation: `Avoid disclosing ${kw.label.toLowerCase()} in public interactions.`
        });
      }
      redactedText = redactedText.replace(kw.pattern, `[${kw.label.toUpperCase()} REDACTED]`);
    }
  }

  // Calculate overall risk level
  let maxScore = 0;
  for (const f of findings) {
    const score = SEVERITY_SCORES[f.severity] || 0;
    if (score > maxScore) maxScore = score;
  }

  let riskLevel = "LOW";
  if (findings.length === 0) riskLevel = "NONE";
  else if (maxScore >= 4 || findings.length >= 4) riskLevel = "CRITICAL";
  else if (maxScore >= 3 || findings.length >= 3) riskLevel = "HIGH";
  else if (maxScore >= 2) riskLevel = "MEDIUM";

  return {
    riskLevel,
    findingsCount: findings.length,
    findings,
    redactedText,
    safe: findings.length === 0
  };
}

// --- Routes ---

// POST /api/scan — Main endpoint for Join39
app.post('/api/scan', (req, res) => {
  const { text, context } = req.body;

  if (!text) {
    return res.status(400).json({
      error: "Missing required parameter: text. Provide the text you want to scan for private information."
    });
  }

  const result = scanText(text);

  const response = {
    riskLevel: result.riskLevel,
    safe: result.safe,
    message: result.safe
      ? "No personal information detected. Safe to share."
      : `Found ${result.findingsCount} privacy concern${result.findingsCount > 1 ? 's' : ''}. Risk level: ${result.riskLevel}. Use the redacted version below for safer sharing.`,
    findingsCount: result.findingsCount,
    findings: result.findings.map(f => ({
      type: f.label,
      severity: f.severity,
      recommendation: f.recommendation
    })),
    redactedText: result.redactedText
  };

  // Add context-specific advice
  if (context) {
    const ctx = context.toLowerCase();
    if (ctx.includes("experience") || ctx.includes("public") || ctx.includes("forum")) {
      response.contextAdvice = "Public experiences are visible to all agents and users. Be extra cautious — share only what is necessary for the interaction.";
    } else if (ctx.includes("chat") || ctx.includes("direct")) {
      response.contextAdvice = "Direct chats are semi-private but the other party may share your information. Avoid sharing sensitive details unless necessary.";
    } else if (ctx.includes("app") || ctx.includes("tool")) {
      response.contextAdvice = "Data sent to third-party apps goes to external servers. Only share parameters the app explicitly requires.";
    }
  }

  return res.json(response);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', app: 'privacy-shield', version: '1.0.0' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Privacy Shield API running on port ${PORT}`);
});
