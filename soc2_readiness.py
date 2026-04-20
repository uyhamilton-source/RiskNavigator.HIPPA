from __future__ import annotations

from typing import Any, Dict, List

import pandas as pd

STATUS_SCORE = {"Yes": 100, "Partial": 50, "No": 0}
SOC2_WEIGHTS = {
    "Control Environment": 0.10,
    "Communication": 0.08,
    "Risk Management": 0.12,
    "Control Activities": 0.12,
    "Logical Access": 0.18,
    "System Operations": 0.15,
    "Change Management": 0.10,
    "Incident Response": 0.10,
    "Availability": 0.03,
    "Confidentiality": 0.02,
}

HIPAA_WEIGHTS = {
    "Administrative Safeguards": 0.34,
    "Physical Safeguards": 0.18,
    "Technical Safeguards": 0.34,
    "Organizational Requirements": 0.08,
    "Policies and Procedures": 0.06,
}

SOC2_CONTROL_LOOKUP = {
    "logical access": "CC6.3",
    "control activities": "CC5.2",
    "system operations": "CC7.1",
    "change management": "CC7.2",
    "incident response": "CC7.3",
    "availability": "A1.2",
    "risk management": "CC3.1",
    "control environment": "CC1.2",
    "communication": "CC2.1",
    "confidentiality": "C1.1",
}

HIPAA_CONTROL_LOOKUP = {
    "logical access": "45 CFR 164.312(a)",
    "control activities": "45 CFR 164.308(a)(1)",
    "system operations": "45 CFR 164.308(a)(8)",
    "change management": "45 CFR 164.312(b)",
    "incident response": "45 CFR 164.308(a)(6)",
    "availability": "45 CFR 164.308(a)(7)",
    "risk management": "45 CFR 164.308(a)(1)(ii)(B)",
    "control environment": "45 CFR 164.308(a)(2)",
    "communication": "45 CFR 164.316",
    "confidentiality": "45 CFR 164.306 / 164.312(e)",
    "administrative safeguards": "45 CFR 164.308",
    "physical safeguards": "45 CFR 164.310",
    "technical safeguards": "45 CFR 164.312",
    "organizational requirements": "45 CFR 164.314",
    "policies and procedures": "45 CFR 164.316",
}

DESIGN_GAP_LOOKUP = {
    "logical access": "No enterprise-wide standard for identity, access, and MFA requirements.",
    "control activities": "Control activities are not fully defined, documented, or tied to accountable owners.",
    "system operations": "Patch and vulnerability management standards are not consistently formalized.",
    "change management": "Logging, monitoring, and change evidence requirements are not clearly defined.",
    "incident response": "Incident response roles, escalation paths, and testing requirements are not fully documented.",
    "availability": "Backup and recovery expectations are not consistently defined or evidenced.",
    "risk management": "Formal risk assessment and review processes are not fully established.",
    "control environment": "Security governance roles and oversight responsibilities are not consistently documented.",
    "communication": "Policy communication and awareness expectations are not consistently established.",
    "confidentiality": "Data handling and confidentiality control requirements are not fully standardized.",
    "administrative safeguards": "Administrative safeguard requirements are not fully documented and assigned to accountable owners.",
    "physical safeguards": "Facility, workstation, and device protection requirements are not fully standardized.",
    "technical safeguards": "Technical safeguard expectations for access, audit controls, and transmission security are not fully defined.",
    "organizational requirements": "Business associate and related organizational obligations are not consistently formalized.",
    "policies and procedures": "HIPAA-specific policies, procedures, and documentation requirements are incomplete or outdated.",
}

IMPLEMENTATION_GAP_LOOKUP = {
    "logical access": "Access controls exist in part, but MFA and access enforcement are not consistently deployed.",
    "control activities": "Control execution varies across teams and supporting evidence is incomplete.",
    "system operations": "Patching and remediation occur inconsistently across systems and time periods.",
    "change management": "Logging and monitoring are present in some areas, but review and retention are inconsistent.",
    "incident response": "Response activities are informal or partially practiced, with limited testing evidence.",
    "availability": "Backups may exist, but restoration testing and supporting records are incomplete.",
    "risk management": "Risk reviews occur inconsistently and are not always tied to formal decisions.",
    "control environment": "Governance expectations are partially in place but not applied uniformly.",
    "communication": "Security communication occurs, but it is not consistently reinforced or evidenced.",
    "confidentiality": "Confidentiality measures are partially implemented but not consistently evidenced.",
    "administrative safeguards": "Administrative safeguards are present in part, but execution and evidence remain inconsistent.",
    "physical safeguards": "Physical controls exist in some locations, but implementation is not consistent across the environment.",
    "technical safeguards": "Technical protections are partially implemented, but coverage and evidence are incomplete.",
    "organizational requirements": "Third-party and organizational obligations are partially addressed, but not consistently evidenced.",
    "policies and procedures": "Policies and procedures exist in part, but updates, approvals, and retention are inconsistent.",
}

SOC2_TO_HIPAA_AREA = {
    "Control Environment": "Administrative Safeguards",
    "Communication": "Policies and Procedures",
    "Risk Management": "Administrative Safeguards",
    "Control Activities": "Administrative Safeguards",
    "Logical Access": "Technical Safeguards",
    "System Operations": "Administrative Safeguards",
    "Change Management": "Technical Safeguards",
    "Incident Response": "Administrative Safeguards",
    "Availability": "Technical Safeguards",
    "Confidentiality": "Technical Safeguards",
}


def normalize_yes_no_partial(value: Any) -> str:
    value = str(value or "").strip()
    if value in STATUS_SCORE:
        return value
    lowered = value.lower()
    if lowered in {"y", "yes", "true", "1"}:
        return "Yes"
    if lowered in {"partial", "some"}:
        return "Partial"
    return "No"


def normalize_yes_no(value: Any) -> str:
    value = str(value or "").strip()
    if value in {"Yes", "No"}:
        return value
    return "Yes" if value.lower() in {"y", "true", "1", "yes"} else "No"


def calc_boolean_bonus(row: Dict[str, Any]) -> int:
    bonus = 0
    bonus_fields = [
        "evidence_available",
        "owner_assigned",
        "policy_exists",
        "procedure_exists",
        "tested_recently",
    ]
    for field in bonus_fields:
        if normalize_yes_no(row.get(field)) == "Yes":
            bonus += 5
    return min(bonus, 25)


def row_score(row: Dict[str, Any]) -> float | None:
    if normalize_yes_no(row.get("in_scope")) != "Yes":
        return None
    base = STATUS_SCORE[normalize_yes_no_partial(row.get("status"))]
    return float(min(base + calc_boolean_bonus(row), 100))


def readiness_band(score: float) -> str:
    if score >= 85:
        return "Ready"
    if score >= 70:
        return "Near Ready"
    if score >= 50:
        return "Developing"
    return "Not Ready"


def load_control_intake(file_obj_or_path: Any) -> pd.DataFrame:
    if hasattr(file_obj_or_path, "read"):
        name = getattr(file_obj_or_path, "name", "").lower()
        if name.endswith(".csv"):
            return pd.read_csv(file_obj_or_path)
        return pd.read_excel(file_obj_or_path, sheet_name="Control Intake")

    path = str(file_obj_or_path)
    if path.lower().endswith(".csv"):
        return pd.read_csv(path)
    return pd.read_excel(path, sheet_name="Control Intake")


def prepare_controls(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns={c: c.strip() for c in df.columns}).copy()
    required = [
        "control_id",
        "control_area",
        "control_name",
        "in_scope",
        "status",
        "evidence_available",
        "owner_assigned",
        "policy_exists",
        "procedure_exists",
        "tested_recently",
    ]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    yn_fields = [
        "in_scope",
        "evidence_available",
        "owner_assigned",
        "policy_exists",
        "procedure_exists",
        "tested_recently",
    ]
    for col in yn_fields:
        df[col] = df[col].apply(normalize_yes_no)

    df["status"] = df["status"].apply(normalize_yes_no_partial)
    df["row_score"] = df.apply(lambda row: row_score(row.to_dict()), axis=1)
    df["priority_hint"] = df["row_score"].apply(
        lambda x: None if pd.isna(x) else ("High" if x < 50 else "Medium" if x < 70 else "Low")
    )
    df["hipaa_area"] = df["control_area"].map(SOC2_TO_HIPAA_AREA).fillna("Administrative Safeguards")
    return df


def build_gap_analysis(in_scope: pd.DataFrame, framework: str = "soc2") -> List[Dict[str, Any]]:
    if in_scope.empty:
        return []

    if framework.lower() == "hipaa":
        lookup = HIPAA_CONTROL_LOOKUP
    else:
        lookup = SOC2_CONTROL_LOOKUP

    gap_candidates = in_scope.sort_values(["row_score", "control_area", "control_id"]).copy()
    gaps: List[Dict[str, Any]] = []
    for _, row in gap_candidates.iterrows():
        if row["row_score"] >= 85:
            continue
        area = str(row["control_area"]).strip()
        area_key = area.lower()
        framework_code = lookup.get(area_key, row["control_id"])
        gaps.append(
            {
                "control": row["control_name"],
                "control_id": row["control_id"],
                "control_area": area,
                "hipaa_area": row.get("hipaa_area", SOC2_TO_HIPAA_AREA.get(area, "Administrative Safeguards")),
                "design_gap": DESIGN_GAP_LOOKUP.get(
                    area_key,
                    "The control requirement is not fully defined, documented, or standardized.",
                ),
                "implementation_gap": IMPLEMENTATION_GAP_LOOKUP.get(
                    area_key,
                    "The control exists in part, but execution and evidence are inconsistent.",
                ),
                "soc2": SOC2_CONTROL_LOOKUP.get(area_key, row["control_id"]),
                "hipaa": HIPAA_CONTROL_LOOKUP.get(area_key, framework_code),
                "status": row["status"],
                "row_score": row["row_score"],
                "priority": "High" if row["row_score"] < 50 else "Medium",
            }
        )
    return gaps[:8]


def build_executive_summary(overall: float, band: str, area_scores: Dict[str, float], gaps: List[Dict[str, Any]], framework_name: str) -> str:
    weakest_areas = sorted(area_scores.items(), key=lambda item: item[1])[:3]
    weakest_text = ", ".join(area for area, _ in weakest_areas) if weakest_areas else "core control areas"
    top_gap_lines = "\n".join(
        f"- {gap['control_id']}: {gap['control']}" for gap in gaps[:3]
    ) or "- No major blockers identified"

    return (
        f"The RiskNavigator™ assessment identified several key cybersecurity and compliance risks that require executive attention. "
        f"The organization currently reflects a {band} level of control maturity, with an overall {framework_name} readiness score of {overall:.1f}. "
        f"Current exposure is driven primarily by gaps in {weakest_text}, where control design and consistency remain underdeveloped.\n\n"
        "Several foundational controls are partially in place, but weaknesses in formal control design, ownership, and evidence collection "
        "increase the risk of operational disruption, audit exceptions, and delayed remediation. These issues may limit the organization’s ability "
        f"to demonstrate readiness for {framework_name} and related stakeholder expectations.\n\n"
        "Immediate focus should be placed on formalizing core security controls, standardizing implementation across in-scope systems, and closing the most material audit blockers listed below.\n\n"
        f"Top blockers:\n{top_gap_lines}"
    )


def _counts_for_in_scope(in_scope: pd.DataFrame) -> Dict[str, int]:
    return {
        "in_scope": int(len(in_scope)),
        "ready": int((in_scope["row_score"] >= 85).sum()),
        "partial": int(((in_scope["row_score"] >= 50) & (in_scope["row_score"] < 85)).sum()),
        "missing": int((in_scope["row_score"] < 50).sum()),
    }


def calculate_soc2_readiness(df: pd.DataFrame) -> Dict[str, Any]:
    in_scope = df[df["in_scope"] == "Yes"].copy()

    if in_scope.empty:
        return {
            "overall_score": 0.0,
            "readiness_band": "Not Ready",
            "area_scores": {},
            "counts": {"in_scope": 0, "ready": 0, "partial": 0, "missing": 0},
            "top_gaps": [],
            "recommendations": [],
            "gaps": [],
            "executive_summary": "No in-scope controls were provided, so readiness could not be determined.",
        }

    area_scores = (
        in_scope.groupby("control_area")["row_score"]
        .mean()
        .round(2)
        .to_dict()
    )

    weighted_total = 0.0
    total_weight = 0.0
    for area, score in area_scores.items():
        weight = SOC2_WEIGHTS.get(area, 0.05)
        weighted_total += score * weight
        total_weight += weight
    overall = round(weighted_total / total_weight, 2) if total_weight else 0.0
    band = readiness_band(overall)

    counts = _counts_for_in_scope(in_scope)

    top_gaps_df = in_scope.sort_values(["row_score", "control_area", "control_id"]).head(8)
    top_gaps = top_gaps_df[[
        "control_id", "control_area", "control_name", "status", "row_score", "priority_hint"
    ]].to_dict(orient="records")

    recommendations = []
    for area, score in sorted(area_scores.items(), key=lambda item: item[1])[:5]:
        recommendations.append(
            {
                "area": area,
                "score": score,
                "priority": "High" if score < 50 else "Medium",
                "recommendation": (
                    "Establish and formally document the control standard, assign accountable ownership, and gather audit-ready evidence."
                    if score < 70
                    else "Complete operating evidence, validate control performance, and prepare walkthrough support for audit review."
                ),
            }
        )

    gaps = build_gap_analysis(in_scope, framework="soc2")
    executive_summary = build_executive_summary(overall, band, area_scores, gaps, "SOC 2")

    return {
        "overall_score": overall,
        "readiness_band": band,
        "area_scores": area_scores,
        "counts": counts,
        "top_gaps": top_gaps,
        "recommendations": recommendations,
        "gaps": gaps,
        "executive_summary": executive_summary,
    }


def calculate_hipaa_readiness(df: pd.DataFrame) -> Dict[str, Any]:
    in_scope = df[df["in_scope"] == "Yes"].copy()

    if in_scope.empty:
        return {
            "overall_score": 0.0,
            "readiness_band": "Not Ready",
            "area_scores": {},
            "counts": {"in_scope": 0, "ready": 0, "partial": 0, "missing": 0},
            "top_gaps": [],
            "recommendations": [],
            "gaps": [],
            "executive_summary": "No in-scope controls were provided, so HIPAA readiness could not be determined.",
        }

    area_scores = (
        in_scope.groupby("hipaa_area")["row_score"]
        .mean()
        .round(2)
        .to_dict()
    )

    weighted_total = 0.0
    total_weight = 0.0
    for area, score in area_scores.items():
        weight = HIPAA_WEIGHTS.get(area, 0.05)
        weighted_total += score * weight
        total_weight += weight
    overall = round(weighted_total / total_weight, 2) if total_weight else 0.0
    band = readiness_band(overall)

    counts = _counts_for_in_scope(in_scope)

    top_gaps_df = in_scope.sort_values(["row_score", "hipaa_area", "control_id"]).head(8)
    top_gaps = top_gaps_df[[
        "control_id", "hipaa_area", "control_name", "status", "row_score", "priority_hint"
    ]].to_dict(orient="records")

    recommendations = []
    for area, score in sorted(area_scores.items(), key=lambda item: item[1])[:5]:
        recommendations.append(
            {
                "area": area,
                "score": score,
                "priority": "High" if score < 50 else "Medium",
                "recommendation": (
                    "Formalize HIPAA safeguard expectations, assign accountable ownership, and collect supporting documentation and evidence."
                    if score < 70
                    else "Complete operating evidence, validate safeguard performance, and prepare documentation to support HIPAA reviews."
                ),
            }
        )

    gaps = build_gap_analysis(in_scope, framework="hipaa")
    executive_summary = build_executive_summary(overall, band, area_scores, gaps, "HIPAA")

    return {
        "overall_score": overall,
        "readiness_band": band,
        "area_scores": area_scores,
        "counts": counts,
        "top_gaps": top_gaps,
        "recommendations": recommendations,
        "gaps": gaps,
        "executive_summary": executive_summary,
    }
