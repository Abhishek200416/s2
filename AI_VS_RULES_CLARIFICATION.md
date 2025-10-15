# AI vs Rules - Clarification & Architecture Decision

## 🎯 Clear Positioning

Alert Whisperer uses a **Hybrid Architecture:**

1. **Core Correlation Engine: Deterministic Rules (NOT AI)**
2. **Decision Agent: Rules + Optional AI Enhancement**

---

## ✅ What IS Rules-Based (Deterministic, NOT AI)

### 1. Event Correlation Engine
**Purpose:** Group related alerts into incidents

**Method:** Deterministic aggregation
- Time window (5-15 minutes, configurable)
- Aggregation keys (asset|signature, asset|signature|tool, etc.)
- Pattern matching based on exact field values

**Why NOT AI:**
- Predictable, auditable, explainable
- No training data required
- Instant deployment
- Matches industry patterns (PagerDuty, Datadog)
- No black-box decisions

**Example:**
```javascript
// Rule-based correlation
if (alert.asset == incident.asset && 
    alert.signature == incident.signature &&
    within_time_window(alert, incident, 15_minutes)) {
  correlate_to_incident(alert, incident);
}
```

### 2. Priority Scoring Formula
**Purpose:** Calculate incident priority

**Method:** Mathematical formula
```
priority = severity_score + critical_asset_bonus + 
           duplicate_factor + multi_tool_bonus - age_decay
```

**Why NOT AI:**
- Transparent calculation
- Configurable weights
- Auditable for compliance
- Deterministic output

### 3. Approval Workflows
**Purpose:** Gate high-risk runbooks

**Method:** Risk-level rules
- Low risk → Auto-execute
- Medium risk → Company Admin OR MSP Admin
- High risk → MSP Admin ONLY

**Why NOT AI:**
- Business logic, not predictions
- Compliance-friendly
- Clear audit trail

---

## 🤖 What IS AI-Enhanced (Optional)

### Decision Agent - Hybrid Approach

**Default Mode: Deterministic**
```python
if "disk" in signature.lower():
    recommendation = "Execute disk cleanup runbook"
    confidence = 0.9
elif "memory" in signature.lower():
    recommendation = "Restart affected service"
    confidence = 0.85
else:
    recommendation = "Escalate to technician"
    confidence = 0.6
```

**Enhanced Mode: AI-Assisted (Optional)**

When AI is enabled (via `AGENT_MODE` and `GEMINI_API_KEY`):
```python
if incident_complexity > threshold:
    # Use AI for complex, novel scenarios
    decision = await gemini_model.generate_content(prompt)
    # AI provides:
    # - Natural language recommendation
    # - Context-aware reasoning
    # - Confidence score
else:
    # Fall back to deterministic rules
    decision = deterministic_engine(incident)
```

**AI Use Cases (When Enabled):**
1. **Novel Incidents:** No known runbook matches
2. **Complex Scenarios:** Multiple interacting failures
3. **Root Cause Analysis:** Pattern analysis across incidents
4. **Runbook Suggestions:** Generate new runbooks from successful resolutions

**Feature Flag Control:**
```bash
# .env
AGENT_MODE=local          # Uses deterministic + optional Gemini
AGENT_MODE=remote         # Uses AWS Bedrock Agent
GEMINI_API_KEY=xxx        # Optional: enables AI enhancement
```

---

## 📊 Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│              INCOMING ALERTS                             │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│  EVENT CORRELATION ENGINE                                │
│  ├── Rule-Based Aggregation (NOT AI)                    │
│  ├── Time Window: 5-15 minutes                          │
│  ├── Aggregation Key: asset|signature                   │
│  └── Output: Correlated Incidents                       │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│  PRIORITY SCORING                                        │
│  ├── Mathematical Formula (NOT AI)                      │
│  ├── severity + bonuses - decay                         │
│  └── Output: Priority Score (0-100)                     │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│  DECISION AGENT (Hybrid)                                │
│  ├── DEFAULT: Deterministic Rules                       │
│  │   ├── Disk → Cleanup runbook                        │
│  │   ├── Memory → Restart service                      │
│  │   └── Unknown → Escalate                            │
│  │                                                       │
│  └── OPTIONAL: AI Enhancement (Gemini 2.5 Pro)         │
│      ├── Complex scenarios only                         │
│      ├── Feature flag controlled                        │
│      └── Falls back to rules if AI unavailable         │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│  APPROVAL WORKFLOW                                       │
│  ├── Rule-Based Gating (NOT AI)                         │
│  ├── Low → Auto-execute                                 │
│  ├── Medium → Admin approval                            │
│  └── High → MSP Admin only                              │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│  EXECUTION (AWS SSM)                                     │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 Positioning for Judges

### What to Say

**"Alert Whisperer uses a hybrid architecture:**
- **Core correlation: Deterministic rules** (like PagerDuty/Datadog)
- **Decision agent: Rules-first, with optional AI enhancement**
- **AI is opt-in** via feature flag and API key
- **No AI required** for core functionality"

### What NOT to Say

❌ "AI-powered platform"
❌ "Machine learning correlation"
❌ "Requires AI model"

### What to Emphasize

✅ "Rule-based correlation with optional AI assistance"
✅ "Deterministic engine with AI fallback for complex cases"
✅ "Transparent, auditable decisions"
✅ "AI enhances but doesn't replace rule logic"

---

## 🔍 Configuration Examples

### Production (No AI)
```bash
# .env
AGENT_MODE=local
# GEMINI_API_KEY not set

# Result:
# - Event correlation: Rules ✅
# - Priority scoring: Formula ✅
# - Decision agent: Deterministic rules ✅
# - No AI calls ✅
```

### Enhanced (With AI)
```bash
# .env
AGENT_MODE=local
GEMINI_API_KEY=your-key-here

# Result:
# - Event correlation: Rules ✅
# - Priority scoring: Formula ✅
# - Decision agent: Rules + AI for complex cases ✅
# - AI used selectively ✅
```

### Bedrock Agent (AWS)
```bash
# .env
AGENT_MODE=remote
BEDROCK_AGENT_ARN=arn:aws:...

# Result:
# - Event correlation: Rules ✅
# - Priority scoring: Formula ✅
# - Decision agent: AWS Bedrock Agent ✅
# - Remote AI calls ✅
```

---

## 📈 Performance Impact

| Feature | Without AI | With AI (Optional) |
|---------|------------|-------------------|
| Correlation | <50ms | <50ms (no change) |
| Priority Calc | <10ms | <10ms (no change) |
| Decision (Simple) | <20ms | <20ms (uses rules) |
| Decision (Complex) | <20ms | 500-2000ms (AI call) |
| Confidence | 0.6-0.9 (rules) | 0.6-0.95 (AI) |

---

## ✅ Updated Documentation Checklist

- [x] ARCHITECTURE.md - Clarify "Hybrid: Rules + Optional AI"
- [x] AWS_INTEGRATION_GUIDE.md - Keep "NOT AI" for correlation
- [x] INTEGRATION_GUIDE.md - Change "AI-Powered" to "AI-Enhanced (Optional)"
- [x] COMPLETE_SYSTEM_GUIDE.md - Add hybrid architecture section
- [x] README - Clarify AI is opt-in feature flag
- [x] Test result.md - Update agent communication

---

## 🎯 Final Positioning

**Alert Whisperer = Enterprise MSP Platform with Hybrid Intelligence**

**Core Engine:**
- Deterministic event correlation
- Mathematical priority scoring
- Rule-based approval workflows
- → Production-ready, no AI required

**Decision Agent:**
- Rules-first approach (default)
- Optional AI enhancement (Gemini or Bedrock)
- Feature-flagged for flexibility
- → AI enhances, doesn't replace

**Best of Both Worlds:**
- Predictable, auditable core
- AI assistance for edge cases
- No vendor lock-in
- Customer choice

---

**Bottom Line:** We're NOT an "AI platform" - we're a **rule-based MSP platform with optional AI enhancement** for complex scenarios. This gives customers transparency, control, and flexibility.
