"""
VaultGuard - AI Rotation Policy Generator (Gemini 2.5 Flash)
Generates structured rotation policy recommendations for each secret category.
"""

import json
import os
from datetime import datetime, timezone
from dotenv import load_dotenv
import requests

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

SECRET_CATEGORIES = [
    {
        "category": "database_credentials",
        "description": "PostgreSQL database username and password used by application services",
        "current_rotation": "manual, approximately every 6 months",
        "consumers": 3,
        "sensitivity": "high",
        "usage_pattern": "persistent connections, connection pooling, accessed by app servers and CI/CD"
    },
    {
        "category": "api_keys",
        "description": "Third-party payment gateway API keys used for transaction processing",
        "current_rotation": "manual, only when compromised",
        "consumers": 2,
        "sensitivity": "critical",
        "usage_pattern": "per-request authentication, accessed by payment microservice and staging environment"
    },
    {
        "category": "service_tokens",
        "description": "Internal service account tokens for monitoring and observability agents",
        "current_rotation": "never rotated since creation",
        "consumers": 5,
        "sensitivity": "medium",
        "usage_pattern": "long-lived tokens, accessed by monitoring agents across all environments"
    },
    {
        "category": "tls_certificates",
        "description": "TLS certificates for web frontend and internal service-to-service communication",
        "current_rotation": "manual renewal before expiry",
        "consumers": 4,
        "sensitivity": "high",
        "usage_pattern": "certificate-based mutual TLS, accessed by load balancers and service mesh"
    }
]


def extract_json_from_gemini_response(result):
    """Extract JSON from Gemini response, handling thinking blocks."""
    candidates = result.get("candidates", [])
    if not candidates:
        return None

    parts = candidates[0].get("content", {}).get("parts", [])

    # Try each part — skip thinking parts, find the one with JSON
    for part in parts:
        # Skip thinking parts
        if part.get("thought", False):
            continue

        text = part.get("text", "")
        if not text:
            continue

        text = text.strip()

        # Strip markdown backticks
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        # Try to find and parse JSON
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start != -1 and json_end > json_start:
            json_text = text[json_start:json_end]
            try:
                return json.loads(json_text)
            except json.JSONDecodeError:
                continue

    # If nothing worked, return the raw text of the last non-thinking part
    for part in reversed(parts):
        if not part.get("thought", False) and part.get("text", ""):
            return {"raw_response": part["text"][:500]}

    return None


def generate_rotation_policy(category_info):
    """Call Gemini to generate a rotation policy for a single secret category."""
    prompt = (
        "You are a security engineer advising on secret rotation policies for a company called Psiog. "
        "Based on the following secret category metadata, generate a structured rotation policy recommendation.\n\n"
        "Secret Category:\n"
        "- Category: " + category_info["category"] + "\n"
        "- Description: " + category_info["description"] + "\n"
        "- Current rotation: " + category_info["current_rotation"] + "\n"
        "- Number of consumers: " + str(category_info["consumers"]) + "\n"
        "- Sensitivity: " + category_info["sensitivity"] + "\n"
        "- Usage pattern: " + category_info["usage_pattern"] + "\n\n"
        "Respond ONLY with a valid JSON object (no markdown, no backticks, no explanation) with these fields:\n"
        "{\n"
        '  "category": "the category name",\n'
        '  "recommended_rotation_interval_days": number,\n'
        '  "rotation_strategy": "description of how to rotate",\n'
        '  "propagation_method": "how to push new secret to all consumers",\n'
        '  "blast_radius_notes": "what happens if rotation fails midway",\n'
        '  "pre_rotation_checks": ["list of checks before rotating"],\n'
        '  "post_rotation_checks": ["list of checks after rotating"],\n'
        '  "justification": "why this interval and strategy"\n'
        "}"
    )

    headers = {"Content-Type": "application/json"}
    params = {"key": GEMINI_API_KEY}
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 4096,
            "thinkingConfig": {"thinkingBudget": 0}
        }
    }

    response = requests.post(GEMINI_URL, headers=headers, params=params, json=body)

    if response.status_code != 200:
        print("  [ERROR] Gemini API returned status " + str(response.status_code))
        print("  " + response.text[:300])
        return None

    result = response.json()
    policy = extract_json_from_gemini_response(result)

    if policy and "raw_response" in policy:
        print("  [WARN] Could not parse as JSON")
        print("  Raw: " + policy["raw_response"][:200])
        policy["category"] = category_info["category"]

    return policy


def generate_all_policies():
    """Generate rotation policies for all 4 secret categories."""
    policies = []

    for category in SECRET_CATEGORIES:
        print("[POLICY] Generating for: " + category["category"])
        policy = generate_rotation_policy(category)
        if policy:
            policies.append(policy)
            interval = policy.get("recommended_rotation_interval_days", "unknown")
            print("  [OK] Recommended interval: " + str(interval) + " days")
        else:
            print("  [FAIL] No policy generated")

    return policies


def save_policies(policies):
    """Save generated policies to file."""
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "Gemini 2.5 Flash",
        "total_categories": len(policies),
        "policies": policies
    }

    output_path = os.path.join("data", "rotation-policies.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print("\n[OK] Rotation policies saved to: " + output_path)
    return output


if __name__ == "__main__":
    print("=" * 50)
    print("VaultGuard - AI Rotation Policy Generator")
    print("=" * 50)

    policies = generate_all_policies()

    print("\n--- Summary ---")
    for p in policies:
        category = p.get("category", "unknown")
        interval = p.get("recommended_rotation_interval_days", "unknown")
        print("  " + category + ": " + str(interval) + " days")

    save_policies(policies)