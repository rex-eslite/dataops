#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import sys
from typing import Iterable, Optional, Dict, Any, List

import pandas as pd
from google.cloud import securitycenter_v2


def _parent_from_scope(org: Optional[str], folder: Optional[str], project: Optional[str]) -> str:
    scopes = [s for s in [org, folder, project] if s]
    if len(scopes) != 1:
        print("❌ 請在 --org / --folder / --project 之間擇一指定。", file=sys.stderr)
        sys.exit(2)

    if org:
        return f"organizations/{org}/sources/-"
    if folder:
        return f"folders/{folder}/sources/-"
    # default: project
    return f"projects/{project}/sources/-"


def list_findings(parent: str, filter_: str = "", page_size: int = 1000) -> Iterable[securitycenter_v2.ListFindingsResponse.ListFindingsResult]:
    client = securitycenter_v2.SecurityCenterClient()
    req = securitycenter_v2.ListFindingsRequest(
        parent=parent,
        filter=filter_ or "",
        page_size=page_size,
    )
    # 會自動分頁
    for item in client.list_findings(request=req):
        yield item


def _safe_ts(ts) -> Optional[str]:
    try:
        return ts.ToDatetime().isoformat() if ts else None
    except Exception:
        return None


def _proto_val_to_python(v) -> Any:
    """將 AnyValue 攤平為 python 原生型別。"""
    if v is None:
        return None
    which = v.WhichOneof("value")
    return getattr(v, which) if which else None


def normalize_rows(findings_iter: Iterable[securitycenter_v2.ListFindingsResponse.ListFindingsResult]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in findings_iter:
        f = item.finding
        r = item.resource

        row: Dict[str, Any] = {
            # Finding 基本欄位
            "finding_name": getattr(f, "name", None),
            "category": getattr(f, "category", None),
            "state": getattr(getattr(f, "state", None), "name", None),
            "severity": getattr(getattr(f, "severity", None), "name", None),
            "finding_class": getattr(getattr(f, "finding_class", None), "name", None),
            "event_time": _safe_ts(getattr(f, "event_time", None)),
            "create_time": _safe_ts(getattr(f, "create_time", None)),
            "description": getattr(f, "description", None),
            "external_uri": getattr(f, "external_uri", None),
            "mute": getattr(getattr(f, "mute", None), "name", None),
            "next_steps": getattr(f, "next_steps", None),

            # Attack Exposure（SCC Premium 才會有值）
            "attack_exposure_score": getattr(getattr(f, "attack_exposure_result", None), "attack_exposure_score", None),

            # Resource context
            "resource_name": getattr(r, "name", None),
            "resource_type": getattr(r, "resource_type", None),
            "project_display_name": getattr(r, "project_display_name", None),
            "project": getattr(r, "project", None),

            # 可能有多層 folder，序列化成 JSON
            "folders": json.dumps([
                {
                    "resource_folder": getattr(fo, "resource_folder", None),
                    "display_name": getattr(fo, "resource_folder_display_name", None),
                }
                for fo in (getattr(r, "folders", []) or [])
            ], ensure_ascii=False) if getattr(r, "folders", None) else None,

            # Security marks
            "security_marks": json.dumps(
                getattr(getattr(f, "security_marks", None), "marks", None),
                ensure_ascii=False
            ) if getattr(getattr(f, "security_marks", None), "marks", None) else None,

            # Source properties（原本是 map<string, AnyValue>）
            "source_properties": json.dumps(
                {k: _proto_val_to_python(v) for k, v in (getattr(f, "source_properties", {}) or {}).items()},
                ensure_ascii=False
            ) if getattr(f, "source_properties", None) else None,

            # IAM 綁定摘要
            "iam_bindings": json.dumps(
                [{"action": getattr(getattr(b, "action", None), "name", None), "role": getattr(b, "role", None)}
                 for b in (getattr(f, "iam_bindings", []) or [])],
                ensure_ascii=False
            ) if getattr(f, "iam_bindings", None) else None,
        }
        rows.append(row)
    return rows


def main():
    ap = argparse.ArgumentParser(description="Export Google Cloud SCC Findings to CSV/JSON (Org/Folder/Project scope).")
    scope = ap.add_mutually_exclusive_group(required=True)
    scope.add_argument("--org", help="Organization ID（無權限時不要用）")
    scope.add_argument("--folder", help="Folder ID")
    scope.add_argument("--project", help="Project ID")

    ap.add_argument("--only_vuln", action="store_true", help="只輸出屬於弱點類（finding_class=\"VULNERABILITY\"）")
    ap.add_argument("--filter", default="", help="SCC filter 語法，可與 --only-vuln 併用，例如：severity=\"HIGH\" AND event_time>=\"-30d\"")
    ap.add_argument("--out", default="scc_findings.csv", help="輸出檔名：.csv 或 .json")
    ap.add_argument("--page-size", type=int, default=1000, help="每頁大小（預設 1000）")

    args = ap.parse_args()

    base_parent = _parent_from_scope(args.org, args.folder, args.project)
    
    vuln_filter = 'finding_class="VULNERABILITY"'
    if args.only_vuln and args.filter:
        final_filter = f"({vuln_filter}) AND ({args.filter})"
    elif args.only_vuln:
        final_filter = vuln_filter
    else:
        final_filter = args.filter

    it = list_findings(parent=base_parent, filter_=final_filter, page_size=args.page_size)
    rows = normalize_rows(it)
    df = pd.DataFrame(rows)

    if args.out.lower().endswith(".json"):
        df.to_json(args.out, orient="records", force_ascii=False, indent=2)
    else:
        df.to_csv(args.out, index=False)

    print(f"✅ Saved {len(df)} rows to {args.out}")


if __name__ == "__main__":
    print(1)
    main()
