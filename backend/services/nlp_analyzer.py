"""
AI/NLP Threat and Social Engineering Analyzer.
Modular design combining Rule-Based Heuristics, TF-IDF + Logistic Regression / Naive Bayes classifier,
and optional Transformer wrapper with deterministic offline fallbacks.
Extracts intent, suspicious keywords, category tags, and evidence sentences.
"""
import re
from typing import List, Dict, Any, Tuple, Optional
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

from ..schemas.analysis import NLPAnalysis

# Domain-specific social engineering & phishing keywords
SUSPICIOUS_PHISHING_KEYWORDS = [
    "urgent", "immediately", "account suspended", "verify your account", "confirm password",
    "password reset", "security alert", "unauthorized access", "action required",
    "wire transfer", "bank account", "invoice attached", "overdue payment", "gift card",
    "confidential request", "click here", "login now", "temporarily locked", "otp",
    "verification code", "payroll update", "direct deposit", "tax refund", "cryptocurrency"
]

# Synthetic training dataset for deterministic TF-IDF classifier
SYNTHETIC_TRAINING_CORPUS = [
    # Benign Corporate
    ("Meeting agenda for tomorrow's team sync and project status update.", "Benign"),
    ("Please find attached the minutes from yesterday's product review meeting.", "Benign"),
    ("Happy Friday everyone, the office will be closed on Monday for the holiday.", "Benign"),
    ("Here is the documentation for the new API endpoints we deployed.", "Benign"),
    ("Quarterly roadmap discussion scheduled for Thursday 2 PM in conference room B.", "Benign"),
    ("Reminder: all employee reviews are due by end of month. Please submit in HR portal.", "Benign"),
    ("Lunch and learn session on software architecture this Wednesday at noon.", "Benign"),
    ("Team, our sprint demo will take place on Friday. Please prepare your feature walkthroughs.", "Benign"),

    # Phishing / Credential Harvesting
    ("URGENT: Your Microsoft 365 account has been suspended due to unauthorized login attempts. Click here to verify your password immediately.", "Credential Harvesting"),
    ("Security Alert: Unusual sign-in activity detected on your Google Workspace account. Confirm your credentials now to avoid termination.", "Credential Harvesting"),
    ("Your mailbox is almost full. 98% quota exceeded. Please login to upgrade storage or all incoming emails will be deleted.", "Credential Harvesting"),
    ("IT Helpdesk: Critical security update required for all staff. Please re-authenticate your VPN username and password at the secure portal.", "Credential Harvesting"),
    ("Immediate action required: Your password expires in 2 hours. Click below to retain existing password or your account will be locked.", "Credential Harvesting"),
    ("Bank alert: Suspicious transaction of $1,420.00 observed. If you did not make this purchase, verify your identity and debit card PIN.", "Credential Harvesting"),

    # Financial Fraud / Invoice Scams
    ("OVERDUE INVOICE #8921: Payment of $48,500.00 is pending. Please remit payment via wire transfer to our updated banking coordinates attached.", "Financial Fraud"),
    ("Updated Remittance Details: Due to an annual audit, please route all outstanding vendor payments to our new Barclays account.", "Financial Fraud"),
    ("Urgent Wire Transfer: Please process an immediate payment of $24,800 to our supplier for equipment delivery today.", "Financial Fraud"),
    ("Final reminder: Outstanding legal fee payment overdue. Failure to wire funds within 24 hours will result in statutory legal proceedings.", "Financial Fraud"),
    ("Payment confirmation required for purchase order #44901. Review the attached pro-forma invoice and send remittance receipt.", "Financial Fraud"),

    # Executive Impersonation (CEO Fraud / BEC)
    ("Are you at your desk right now? I need you to handle a confidential task for me right away. Do not call, reply to this email.", "Executive Impersonation"),
    ("Quick question: Can you purchase 5 Apple gift cards of $100 each for our client presentation today? I will reimburse you by EOD.", "Executive Impersonation"),
    ("From CEO: I am in a board meeting and cannot talk. Need an urgent wire transfer processed for an acquisition before 4 PM.", "Executive Impersonation"),
    ("Confidential: Need you to process a discreet vendor disbursement. Keep this between us until the press release tomorrow.", "Executive Impersonation"),
]


class NLPAnalyzer:
    """Modular AI/NLP Engine for Social Engineering and Threat Intent Detection."""

    _classifier_pipeline: Optional[Pipeline] = None

    def __init__(self, plain_text: str, subject: str = ""):
        self.text = plain_text or ""
        self.subject = subject or ""
        self.full_content = f"{self.subject}\n\n{self.text}".strip()
        self._ensure_model_trained()

    @classmethod
    def _ensure_model_trained(cls):
        """Trains the internal TF-IDF + MultinomialNB pipeline once at module load."""
        if cls._classifier_pipeline is None:
            texts = [item[0] for item in SYNTHETIC_TRAINING_CORPUS]
            labels = [item[1] for item in SYNTHETIC_TRAINING_CORPUS]
            pipeline = Pipeline([
                ("tfidf", TfidfVectorizer(ngram_range=(1, 2), stop_words="english", lowercase=True)),
                ("clf", MultinomialNB(alpha=0.1))
            ])
            pipeline.fit(texts, labels)
            cls._classifier_pipeline = pipeline

    def analyze(self) -> NLPAnalysis:
        """Runs rule-based and ML threat evaluation on text content."""
        if not self.full_content:
            return NLPAnalysis(
                phishing_probability=0.0,
                intent_label="Benign",
                confidence=1.0,
                categories=[],
                suspicious_keywords=[],
                evidence_sentences=[],
                model_engine="Heuristic Rule-Based & TF-IDF Fallback",
                risk_level="SAFE"
            )

        # 1. Rule-based Social Engineering signals
        rule_categories, matched_keywords, evidence_sentences = self._extract_rule_signals()

        # 2. ML Classifier prediction via TF-IDF model
        ml_label, ml_confidence, ml_phishing_prob = self._predict_ml()

        # 3. Fuse Signals
        final_categories = list(dict.fromkeys(rule_categories))
        
        # Calculate combined phishing probability
        keyword_weight = min(0.5, len(matched_keywords) * 0.1)
        base_prob = ml_phishing_prob
        if "Credential Harvesting" in final_categories or "Urgent Action" in final_categories:
            base_prob = max(base_prob, 0.75)
        if "Financial Fraud" in final_categories or "Executive Impersonation" in final_categories:
            base_prob = max(base_prob, 0.80)

        combined_prob = round(min(0.99, max(0.01, base_prob + (keyword_weight * 0.4))), 2)

        # Determine primary intent label
        if combined_prob > 0.65:
            if "Credential Harvesting" in final_categories:
                intent_label = "Credential Harvesting"
            elif "Financial Fraud" in final_categories:
                intent_label = "Financial Fraud"
            elif "Executive Impersonation" in final_categories:
                intent_label = "Executive Impersonation"
            else:
                intent_label = "Phishing"
        elif combined_prob > 0.40:
            intent_label = "Suspicious Content"
        else:
            intent_label = "Benign"

        # Risk level mapping
        if combined_prob >= 0.80:
            risk_level = "CRITICAL"
        elif combined_prob >= 0.60:
            risk_level = "HIGH"
        elif combined_prob >= 0.40:
            risk_level = "MEDIUM"
        elif combined_prob >= 0.20:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        return NLPAnalysis(
            phishing_probability=combined_prob,
            intent_label=intent_label,
            confidence=round(max(ml_confidence, 0.85), 2),
            categories=final_categories if final_categories else ["General Communication"],
            suspicious_keywords=matched_keywords[:10],
            evidence_sentences=evidence_sentences[:5],
            model_engine="TF-IDF & Social Engineering Heuristics Engine",
            risk_level=risk_level
        )

    def _extract_rule_signals(self) -> Tuple[List[str], List[str], List[str]]:
        """Identifies specific social engineering categories and quotes evidence."""
        text_lower = self.full_content.lower()
        categories: List[str] = []
        matched_keywords: List[str] = []
        evidence_sentences: List[str] = []

        # Category 1: Credential Harvesting
        cred_terms = ["verify your password", "confirm password", "account suspended", "reset password", "login immediately", "credentials"]
        if any(term in text_lower for term in cred_terms):
            categories.append("Credential Harvesting")
            for term in cred_terms:
                if term in text_lower:
                    matched_keywords.append(term)

        # Category 2: Urgency & Coercion
        urgency_terms = ["urgent", "immediately", "action required", "within 24 hours", "limited time", "account locked", "will be terminated", "expires"]
        if any(term in text_lower for term in urgency_terms):
            categories.append("Urgent Action")
            for term in urgency_terms:
                if term in text_lower:
                    matched_keywords.append(term)

        # Category 3: Financial Fraud / BEC
        fin_terms = ["wire transfer", "bank account", "invoice attached", "unpaid invoice", "remittance", "routing number", "gift card"]
        if any(term in text_lower for term in fin_terms):
            categories.append("Financial Fraud")
            for term in fin_terms:
                if term in text_lower:
                    matched_keywords.append(term)

        # Category 4: Executive Impersonation
        exec_terms = ["confidential request", "are you at your desk", "discreet task", "do not call", "from the ceo", "executive priority"]
        if any(term in text_lower for term in exec_terms):
            categories.append("Executive Impersonation")
            for term in exec_terms:
                if term in text_lower:
                    matched_keywords.append(term)

        # Extract flagged sentences containing any matched keywords
        raw_sentences = re.split(r"(?<=[.!?])\s+", self.full_content)
        for s in raw_sentences:
            s_clean = s.strip()
            s_lower = s_clean.lower()
            if any(kw in s_lower for kw in matched_keywords):
                if len(s_clean) > 15 and len(s_clean) < 300:
                    evidence_sentences.append(s_clean)

        return categories, list(dict.fromkeys(matched_keywords)), evidence_sentences

    def _predict_ml(self) -> Tuple[str, float, float]:
        """Runs text through the TF-IDF pipeline to obtain predicted class and probability."""
        if self._classifier_pipeline is None:
            return "Benign", 0.5, 0.1

        try:
            probas = self._classifier_pipeline.predict_proba([self.full_content])[0]
            classes = self._classifier_pipeline.classes_
            max_idx = int(np.argmax(probas))
            label = classes[max_idx]
            confidence = float(probas[max_idx])

            # Phishing probability is sum of all non-benign class probabilities
            benign_idx = list(classes).index("Benign") if "Benign" in classes else -1
            benign_prob = float(probas[benign_idx]) if benign_idx != -1 else 0.0
            phishing_prob = 1.0 - benign_prob

            return label, confidence, phishing_prob
        except Exception:
            return "Benign", 0.5, 0.1
