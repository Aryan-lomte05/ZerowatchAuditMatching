"""
ZEROWATCH CVE MATCHING - HYBRID SYSTEM
Transparent 2-Stage Pipeline: String Matching → AI Verification (Ollama Llama 3)
"""

import json
import os
import time
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

import hashlib

import ollama
import pandas as pd
from rapidfuzz import fuzz, process

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

print("=" * 80)
print("ZEROWATCH HYBRID CVE MATCHING SYSTEM")
print("Stage 1: String Matching (Token Sort + Partial Ratio)")
print("Stage 2: AI Verification (Ollama Llama 3)")
print("=" * 80 + "\n")


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Configuration from environment"""

    # Matching parameters
    TOP_K_TOKEN_SORT = int(os.getenv('TOP_K_TOKEN_SORT', '10'))
    TOP_K_PARTIAL_RATIO = int(os.getenv('TOP_K_PARTIAL_RATIO', '10'))

    # Be stricter: aim for high precision (fewer, but more correct matches)
    CONFIDENCE_THRESHOLD = float(os.getenv('CONFIDENCE_THRESHOLD', '0.85'))
    # Minimum required similarity between installed publisher and matched vendor
    MIN_VENDOR_SIMILARITY = float(os.getenv('MIN_VENDOR_SIMILARITY', '0.7'))
  
    # Optional limits (still used if you ever go back to remote models; harmless here)
    MAX_GEMINI_CALLS = int(os.getenv('MAX_GEMINI_CALLS', '1000'))      # global per run
    MAX_CALLS_PER_KEY = int(os.getenv('MAX_CALLS_PER_KEY', '200'))     # per key per run

    # Paths
    PROJECT_ROOT = Path(__file__).parent.parent
    DATA_DIR = PROJECT_ROOT / 'data'
    OUTPUT_DIR = PROJECT_ROOT / 'output'
    LOGS_DIR = OUTPUT_DIR / 'transparent_logs'
    GEMINI_CACHE_PATH = OUTPUT_DIR / 'gemini_cache.jsonl'  # reused for Ollama cache
    FINAL_DIR = OUTPUT_DIR / 'final_matching_data'
    OLLAMA_MODEL = "llama3"

    @staticmethod
    def load_api_keys() -> Dict[str, str]:
        """
        Left as-is if you no longer use Gemini.
        If you're only on Ollama now, you can even make this just return {}.
        """
        return {}



# ============================================================================
# LOAD DATABASE
# ============================================================================

def load_cve_database(csv_path: Optional[str] = None) -> List[Dict]:
    """Load CPE products database (vendor, product, optional version)."""

    if not csv_path:
        csv_path = Config.DATA_DIR / 'products_export.csv'

    print(f"📂 Loading CVE database: {csv_path}")

    if not os.path.exists(csv_path):
        print(f"❌ ERROR: Database not found at {csv_path}")
        print("   Please copy products_export.csv to data/ directory")
        return []

    df = pd.read_csv(csv_path)

    # Auto-detect vendor/product/version columns
    vendor_candidates = [c for c in df.columns if 'vendor' in c.lower()]
    product_candidates = [c for c in df.columns if 'product' in c.lower()]
    version_candidates = [c for c in df.columns if 'version' in c.lower()]

    if not vendor_candidates or not product_candidates:
        raise ValueError(
            f"Could not auto-detect vendor/product columns in {csv_path}. "
            f"Columns found: {list(df.columns)}"
        )

    vendor_col = vendor_candidates[0]
    product_col = product_candidates[0]
    version_col = version_candidates[0] if version_candidates else None

    if version_col:
        print(f"   Detected columns: {vendor_col}, {product_col}, {version_col}")
    else:
        print(f"   Detected columns: {vendor_col}, {product_col}")

    products: List[Dict] = []
    for _, row in df.iterrows():
        vendor = str(row[vendor_col]).lower().strip()
        product = str(row[product_col]).lower().strip()
        version = str(row[version_col]).lower().strip() if version_col else ""

        if vendor and product and vendor != "nan" and product != "nan":
            search_parts = [vendor, product]
            if version and version != "nan":
                search_parts.append(version)
            search_text = " ".join(search_parts)

            products.append({
                'vendor': vendor,
                'product': product,
                'version': version,
                'canonical': f"{vendor}/{product}",
                'search_text': search_text,
            })

    print(f"✅ Loaded {len(products):,} products\n")
    return products



# ============================================================================
# NORMALIZATION
# ============================================================================

# Precompile noise patterns for speed
_NOISE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r'\(64-bit\)', r'\(x64\)', r'\(x86\)', r'\(32-bit\)',
        r'\bversion\b', r'\bv\d+\.\d+', r'\bx64\b', r'\bx86\b',
        r'\d+\.\d+\.\d+\.\d+', r'\d+\.\d+\.\d+',
        r'\(remove only\)', r'\(64 bit\)', r'\(32 bit\)',
        r'\.exe$', r'\.msi$', r'\.app$',
        r'\s+update\s+\d+', r'\s+sp\d+',
        r'microsoft\s+visual\s+c\+\+',
    ]
]


def normalize_software_name(name: str) -> str:
    """Normalize software name by removing noise."""
    name = str(name).lower()

    for pattern in _NOISE_PATTERNS:
        name = pattern.sub('', name)

    return ' '.join(name.split()).strip()


def rerank_candidates_with_publisher(
    candidates: List[Dict[str, Any]],
    publisher: str
) -> List[Dict[str, Any]]:
    publisher = (publisher or "").strip()
    if not publisher:
        return candidates

    pub_norm = publisher.lower()
    adjusted: List[Dict[str, Any]] = []

    for cand in candidates:
        vendor = (cand.get("vendor") or "").strip().lower()

        if vendor:
            vendor_match = fuzz.partial_ratio(pub_norm, vendor) / 100.0
        else:
            vendor_match = 0.0

        base_score = float(cand.get("score", 0.0))
        cand = dict(cand)
        cand["vendor_match_score"] = vendor_match

        if vendor_match < 0.3:
            new_score = base_score * 0.25
        elif vendor_match < 0.6:
            new_score = base_score * 0.7
        else:
            new_score = min(1.0, base_score * (0.9 + 0.2 * vendor_match))

        cand["score"] = new_score
        adjusted.append(cand)

    adjusted.sort(key=lambda x: x["score"], reverse=True)
    return adjusted


# ============================================================================
# STAGE 1: STRING MATCHING (TRANSPARENT)
# ============================================================================

from rapidfuzz import fuzz, process


def get_candidates_token_sort(
    query: str,
    search_texts: List[str],
    db_products: List[Dict],
    top_k: int
) -> List[Dict]:
    """
    Stage 1A: WRatio – robust overall fuzzy score.
    """

    matches = process.extract(
        query,
        search_texts,
        scorer=fuzz.WRatio,
        limit=top_k
    )

    candidates: List[Dict] = []
    for matched_text, score, idx in matches:
        product = db_products[idx]
        candidates.append({
            'vendor': product['vendor'],
            'product': product['product'],
            'version': product.get('version'),
            'canonical': product['canonical'],
            'score': score / 100.0,
            'method': 'wratio',
            'matched_text': matched_text,
        })

    return candidates


def get_candidates_partial_ratio(
    query: str,
    search_texts: List[str],
    db_products: List[Dict],
    top_k: int
) -> List[Dict]:
    """
    Stage 1B: token_set_ratio – focuses on unordered token overlap,
    much safer than raw partial_ratio.
    """

    matches = process.extract(
        query,
        search_texts,
        scorer=fuzz.token_set_ratio,
        limit=top_k
    )

    candidates: List[Dict] = []
    for matched_text, score, idx in matches:
        product = db_products[idx]
        candidates.append({
            'vendor': product['vendor'],
            'product': product['product'],
            'version': product.get('version'),
            'canonical': product['canonical'],
            'score': score / 100.0,
            'method': 'token_set',
            'matched_text': matched_text,
        })

    return candidates


def get_all_candidates(
    query: str,
    db_products: List[Dict],
    search_texts: List[str]
) -> Dict:
    """
    STAGE 1: Get candidates from BOTH algorithms.
    Returns transparent structure showing all candidates.
    Includes special handling for very short names like "git", "vlc".
    """

    short_query = query.strip()
    is_very_short = len(short_query) <= 3

    if is_very_short:
        # For tiny names, be extremely conservative:
        #  - only consider rows where the short token appears as a standalone word
        #  - use WRatio but still keep K small
        token_sort_candidates: List[Dict] = []
        for idx, text in enumerate(search_texts):
            text_l = str(text).lower()
            if short_query == text_l or f" {short_query} " in f" {text_l} ":
                score = fuzz.WRatio(short_query, text_l) / 100.0
                product = db_products[idx]
                token_sort_candidates.append({
                    'vendor': product['vendor'],
                    'product': product['product'],
                    'version': product.get('version'),
                    'canonical': product['canonical'],
                    'score': score,
                    'method': 'short_exact',
                    'matched_text': text,
                })

        token_sort_candidates = sorted(
            token_sort_candidates,
            key=lambda x: x['score'],
            reverse=True
        )[:Config.TOP_K_TOKEN_SORT]

        partial_ratio_candidates: List[Dict] = []

    else:
        token_sort_candidates = get_candidates_token_sort(
            query, search_texts, db_products, Config.TOP_K_TOKEN_SORT
        )

        partial_ratio_candidates = get_candidates_partial_ratio(
            query, search_texts, db_products, Config.TOP_K_PARTIAL_RATIO
        )

    # Combine and deduplicate by canonical
    all_candidates: Dict[str, Dict] = {}
    for candidate in token_sort_candidates + partial_ratio_candidates:
        key = candidate['canonical']
        if key not in all_candidates:
            all_candidates[key] = candidate
        else:
            # Keep candidate with higher score
            if candidate['score'] > all_candidates[key]['score']:
                all_candidates[key] = candidate

    sorted_candidates = sorted(
        all_candidates.values(),
        key=lambda x: x['score'],
        reverse=True
    )

    return {
        'token_sort_top10': token_sort_candidates,
        'partial_ratio_top10': partial_ratio_candidates,
        'combined_unique': sorted_candidates,
        'total_unique_candidates': len(sorted_candidates),
    }



# ============================================================================
# STAGE 2: AI VERIFICATION (TRANSPARENT, OLLAMA)
# ============================================================================

import ollama
import hashlib


class AIVerifier:
    """
    AI verifier using Ollama (e.g., llama3) with:
    - persistent caching
    - JSON-only protocol
    - robust JSON extraction
    - confidence tied to Stage-1 similarity
    """

    def __init__(self, model_name: str):
        self.model_name = model_name
        self.cache_path = Config.GEMINI_CACHE_PATH  # reuse existing cache path
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.total_calls: int = 0
        self._load_cache()
        print(f"✅ AI verifier initialized with Ollama model: {self.model_name}\n")

    # -------------------------
    # CACHE HANDLING
    # -------------------------

    def _load_cache(self) -> None:
        """Load cached AI decisions from disk (jsonl)."""
        if not self.cache_path.exists():
            return

        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    key = entry["key"]
                    result = entry["result"]
                    self.cache[key] = result
            print(f"📦 AI cache loaded: {len(self.cache)} entries")
        except Exception as e:
            print(f"⚠️  Failed to load AI cache: {e}")

    ALGO_VERSION = "v2"  # bump this whenever you change logic significantly

    def _make_cache_key(self, original_name: str, candidates: List[Dict[str, Any]]) -> str:
        """
        Stable cache key based on:
        - original software name
        - top candidate canonicals
        - current algorithm version
        """
        norm_name = str(original_name).strip().lower()
        top_canonicals = [c["canonical"] for c in candidates[:10]]
        payload = {
            "algo_version": self.ALGO_VERSION,
            "original_name": norm_name,
            "top_candidates": top_canonicals,
        }
        raw = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


    def _get_from_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        result = self.cache.get(cache_key)
        if result is None:
            return None
        # return a deep copy
        return json.loads(json.dumps(result))

    def _save_to_cache(self, cache_key: str, core_result: Dict[str, Any]) -> None:
        """Append a new entry to the cache file & in-memory dict."""
        self.cache[cache_key] = core_result
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"key": cache_key, "result": core_result}) + "\n")
        except Exception as e:
            print(f"⚠️  Failed to write AI cache entry: {e}")

    # -------------------------
    # JSON EXTRACTION HELPERS
    # -------------------------

    def _extract_json_block(self, text: str) -> str:
        """
        Try hard to find a JSON object in the model output.
        Handles:
        - bare JSON
        - ```json ... ``` fenced blocks
        - text + JSON + text
        """
        if not text:
            raise ValueError("Empty response from AI model")

        text = text.strip()

        # case 1: looks like pure JSON already
        if text.lstrip().startswith("{") and text.rstrip().endswith("}"):
            return text

        # case 2: code fences ```...``` or ```json ... ```
        if "```" in text:
            parts = text.split("```")
            for segment in parts:
                segment = segment.strip()
                if not segment:
                    continue
                # drop a leading language hint like "json"
                if segment.lower().startswith("json"):
                    segment = segment[4:].strip()
                if segment.startswith("{") and segment.endswith("}"):
                    return segment

        # case 3: find the first {...} block in the string
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = text[start : end + 1].strip()
            if candidate.startswith("{") and candidate.endswith("}"):
                return candidate

        # if we reach here, we really couldn’t find JSON
        raise ValueError(f"Could not locate JSON object in AI output: {text[:200]!r}")

    # -------------------------
    # MAIN CALL
    # -------------------------
    
    def verify_match(
        self,
        original_name: str,
        candidates: List[Dict[str, Any]],
        original_version: str = "",
        original_publisher: str = "",
    ) -> Dict[str, Any]:
        """
        Ask Ollama to select best match from candidates, with cache + fallback.

        `original_version` and `original_publisher` are accepted for backward
        compatibility (some callers pass them as keyword arguments), but we
        currently don't use them inside the LLM prompt.
        """

        cache_key = self._make_cache_key(original_name, candidates)
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            cached["from_cache"] = True
            cached.setdefault("total_candidates_provided", len(candidates))
            cached.setdefault("ai_model", self.model_name)
            cached.setdefault("ai_response_time_ms", 0)
            return cached

        # Build candidate list for the prompt
        candidates_lines = []
        for i, candidate in enumerate(candidates[:20], 1):
            cand_line = (
                f"{i}. {candidate['canonical']} "
                f"(score: {candidate['score']:.2%}, method: {candidate['method']})"
            )
            candidates_lines.append(cand_line)
        candidates_text = "\n".join(candidates_lines)

        # Very strict JSON-only instructions
        prompt = f"""
You are a software product matching expert for cybersecurity CVE auditing.

TASK: Match the installed software to the correct CVE database product.

INSTALLED SOFTWARE:
"{original_name}"

CANDIDATE MATCHES FROM DATABASE (scored by string similarity):
{candidates_text}

INSTRUCTIONS:
1. Analyze the original software name carefully.
2. Compare against all candidates.
3. Select the SINGLE BEST match.
4. If NO candidate matches confidently, return "matched": false.
5. YOU MUST RESPOND WITH **ONLY** A JSON OBJECT. NO extra text, NO markdown, NO explanation outside JSON.

VALID JSON RESPONSE IF A MATCH EXISTS:
{{
  "matched": true,
  "selected_canonical": "vendor/product",
  "confidence": 0.92,
  "reasoning": "Brief explanation",
  "alternatives_considered": ["vendor2/product2"]
}}

VALID JSON RESPONSE IF NO MATCH:
{{
  "matched": false,
  "selected_canonical": "",
  "confidence": 0.0,
  "reasoning": "Why none match",
  "alternatives_considered": []
}}
""".strip()

        # Call Ollama
        try:
            import ollama

            self.total_calls += 1
            start_time = time.time()
            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You strictly output only JSON."},
                    {"role": "user", "content": prompt},
                ],
            )
            ai_time = time.time() - start_time

            raw_text = (response.get("message", {}).get("content") or "").strip()
            json_block = self._extract_json_block(raw_text)
            parsed = json.loads(json_block)

            # --- tie AI confidence to Stage-1 similarity ---
            selected_canonical = parsed.get("selected_canonical", "")
            stage1_score = 0.0
            if selected_canonical:
                for cand in candidates:
                    if cand["canonical"] == selected_canonical:
                        stage1_score = float(cand.get("score", 0.0))
                        break

            model_confidence = float(parsed.get("confidence", 0.0))
            combined_confidence = min(model_confidence, stage1_score)

            core: Dict[str, Any] = dict(parsed)
            core["model_confidence_raw"] = model_confidence
            core["stage1_similarity_score"] = stage1_score
            core["confidence"] = combined_confidence
            core["ai_model"] = self.model_name
            core["ai_response_time_ms"] = round(ai_time * 1000, 2)
            core["ai_raw_response"] = raw_text[:500]
            core["total_candidates_provided"] = len(candidates)

            if core.get("matched") and core.get("selected_canonical"):
                canonical = core["selected_canonical"]
                if "/" in canonical:
                    vendor, product = canonical.split("/", 1)
                    core["vendor"] = vendor
                    core["product"] = product

            self._save_to_cache(cache_key, core)
            return core

        except Exception as e:
            # This is where "AI verification failed: ..." messages come from
            msg = str(e)
            print(f"⚠️  AI verification failed: {msg[:150]}")

            # Fallback: use highest stage-1 string match
            best = candidates[0]
            core = {
                "matched": True,
                "selected_canonical": best["canonical"],
                "vendor": best["vendor"],
                "product": best["product"],
                "confidence": float(best["score"]),
                "reasoning": "AI backend (Ollama) unavailable or invalid JSON, using highest string match",
                "fallback_used": True,
                "ai_model": self.model_name,
                "ai_response_time_ms": 0,
                "ai_raw_response": "",
                "total_candidates_provided": len(candidates),
            }

            self._save_to_cache(cache_key, core)
            return core

    # -------------------------
    # STATS
    # -------------------------

    def print_usage_stats(self) -> None:
        print("\n" + "=" * 80)
        print("AI VERIFICATION (OLLAMA) USAGE STATISTICS")
        print("=" * 80 + "\n")
        print(f"  Model:         {self.model_name}")
        print(f"  Total AI calls this run: {self.total_calls}")
        print(f"  Cache size:    {len(self.cache)} entries\n")




# ============================================================================
# HYBRID MATCHER (MAIN PIPELINE)
# ============================================================================

class HybridMatcher:
    """Complete transparent hybrid matching pipeline"""

    def __init__(self, db_products: List[Dict]):
        self.db_products = db_products
        self.search_texts = [p['search_text'] for p in db_products]
        self.ai = AIVerifier(Config.OLLAMA_MODEL)

        self.stats = {
            'total': 0,
            'matched': 0,
            'ai_verified': 0,
            'string_fallback': 0,
            'failed': 0,
            'processing_times': [],
        }

    def _apply_confidence_threshold(self, result: Dict) -> Dict:
        """
        Enforce global confidence threshold on final match.
        If below threshold, treat as no match.
        """
        if not result.get('matched'):
            return result

        confidence = float(result.get('confidence', 0.0))
        if confidence < Config.CONFIDENCE_THRESHOLD:
            reason = result.get('reasoning', '')
            threshold_note = (
                f"Marked as NO_MATCH because confidence "
                f"{confidence:.2f} < threshold {Config.CONFIDENCE_THRESHOLD:.2f}"
            )
            if reason:
                reason = reason + " | " + threshold_note
            else:
                reason = threshold_note

            result['matched'] = False
            result['reasoning'] = reason

        return result

    def match_single(self, software_name: str, version: str = '', publisher: str = '') -> Dict:
        """Complete transparent matching for one software item"""

        self.stats['total'] += 1
        start_time = time.time()

        # Stage 1: String matching
        normalized = normalize_software_name(software_name)
        stage1_start = time.time()
        stage1_result = get_all_candidates(normalized, self.db_products, self.search_texts)
        stage1_time = time.time() - stage1_start

        # Re-rank combined candidates using publisher/vendor info
        if stage1_result['combined_unique'] and publisher:
            stage1_result['combined_unique'] = rerank_candidates_with_publisher(
                stage1_result['combined_unique'],
                publisher
            )

        # Default empty result in case of no candidates
        if not stage1_result['combined_unique']:
            result = {
                'original_name': software_name,
                'original_version': version,
                'original_publisher': publisher,
                'normalized_query': normalized,
                'stage1_string_matching': {
                    'token_sort_top10': stage1_result['token_sort_top10'],
                    'partial_ratio_top10': stage1_result['partial_ratio_top10'],
                    'combined_unique_candidates': [],
                    'total_unique': 0,
                    'processing_time_ms': round(stage1_time * 1000, 2),
                },
                'stage2_gemini_verification': {
                    'status': 'skipped',
                    'reason': 'no_candidates_found',
                },
                'matched': False,
                'reason': 'no_candidates_found',
                'total_processing_time_ms': round((time.time() - start_time) * 1000, 2),
                'timestamp': datetime.now().isoformat(),
            }
            self.stats['failed'] += 1
            self.stats['processing_times'].append(result['total_processing_time_ms'])
            return result

        # Stage 2: AI verification
        ai_raw_result = self.ai.verify_match(
            software_name,
            stage1_result['combined_unique'],
        )

        ai_result = {**ai_raw_result}

        # --- FAST-PATH: rescue near-exact vendor/product matches ---
        product_name = str(ai_result.get('product') or '').strip()
        vendor_name = str(ai_result.get('vendor') or '').strip()

        if product_name:
            # Thresholds tuned for precision > recall
            FASTPATH_MIN_NAME_SIM = 0.95   # product name ~exact to installed name
            FASTPATH_MIN_VENDOR_SIM = 0.80 # vendor fairly strong match

            sw_norm = str(software_name).strip().lower()
            prod_norm = product_name.lower()
            name_sim = fuzz.partial_ratio(sw_norm, prod_norm) / 100.0

            pub_norm = str(publisher or '').strip().lower()
            vend_norm = vendor_name.lower() if vendor_name else ''
            vendor_sim = 0.0
            if pub_norm and vend_norm:
                vendor_sim = fuzz.partial_ratio(pub_norm, vend_norm) / 100.0

            # Force match if:
            #  - name is almost exact, and
            #  - either no publisher OR vendor similarity is strong
            if name_sim >= FASTPATH_MIN_NAME_SIM and (not pub_norm or vendor_sim >= FASTPATH_MIN_VENDOR_SIM):
                prev_conf = float(ai_result.get('confidence', 0.0))
                ai_result['matched'] = True
                ai_result['confidence'] = max(prev_conf, 0.97)

                if not ai_result.get('selected_canonical') and vendor_name and product_name:
                    ai_result['selected_canonical'] = f"{vendor_name}/{product_name}"

                note = (
                    f"Forced match via fast-path: near-exact product name "
                    f"(similarity={name_sim:.2f})"
                )
                if pub_norm and vend_norm:
                    note += f", vendor similarity={vendor_sim:.2f}"

                prev_reason = ai_result.get('reasoning', '')
                ai_result['reasoning'] = (prev_reason + " | " + note) if prev_reason else note

        # --- vendor sanity check (precision > recall) ---
        # If we have an installed publisher and AI gave us a vendor, ensure they roughly match.
        if ai_result.get('matched') and publisher and ai_result.get('vendor'):
            pub_norm = str(publisher).strip().lower()
            vendor_norm = str(ai_result['vendor']).strip().lower()
            if pub_norm and vendor_norm:
                vendor_sim = fuzz.partial_ratio(pub_norm, vendor_norm) / 100.0
                stage1_score = float(ai_result.get("stage1_similarity_score", 0.0))
                # Only demote when BOTH:
                #  1) vendor similarity is low
                #  2) string similarity from Stage 1 is not extremely strong
                if vendor_sim < Config.MIN_VENDOR_SIMILARITY and stage1_score < 0.90:
                    note = (
                        f"Vendor mismatch: installed publisher '{publisher}' vs "
                        f"matched vendor '{ai_result['vendor']}' "
                        f"(similarity {vendor_sim:.2f} < {Config.MIN_VENDOR_SIMILARITY:.2f}, "
                        f"stage1_similarity={stage1_score:.2f})"
                    )
                    prev_reason = ai_result.get('reasoning', '')
                    ai_result['reasoning'] = (prev_reason + " | " + note) if prev_reason else note
                    ai_result['matched'] = False

        # Apply global confidence threshold (very strict)
        ai_result = self._apply_confidence_threshold(ai_result)
        matched_flag = ai_result.get('matched', False)

        result = {
            'original_name': software_name,
            'original_version': version,
            'original_publisher': publisher,
            'normalized_query': normalized,
            'stage1_string_matching': {
                'token_sort_top10': stage1_result['token_sort_top10'],
                'partial_ratio_top10': stage1_result['partial_ratio_top10'],
                'combined_unique_candidates': stage1_result['combined_unique'],
                'total_unique': stage1_result['total_unique_candidates'],
                'processing_time_ms': round(stage1_time * 1000, 2),
            },
            'stage2_gemini_verification': ai_result,
            'matched': matched_flag,
            'final_vendor': ai_result.get('vendor'),
            'final_product': ai_result.get('product'),
            'final_canonical': ai_result.get('selected_canonical'),
            'final_confidence': ai_result.get('confidence', 0.0),
            'total_processing_time_ms': round((time.time() - start_time) * 1000, 2),
            'timestamp': datetime.now().isoformat(),
        }

        if matched_flag:
            self.stats['matched'] += 1
            if ai_result.get('fallback_used'):
                self.stats['string_fallback'] += 1
            else:
                self.stats['ai_verified'] += 1
        else:
            self.stats['failed'] += 1

        self.stats['processing_times'].append(result.get('total_processing_time_ms', 0.0))
        return result



    def batch_match(self, software_list: List[Dict]) -> List[Dict]:
        """Match a batch of software with progress tracking"""

        from tqdm import tqdm

        results: List[Dict] = []

        print(f"Processing {len(software_list)} software items...\n")

        for item in tqdm(software_list, desc="Matching", unit="item"):
            if isinstance(item, dict):
                name = item.get('name', '') or item.get('original_name', '')
                version = item.get('version', '')
                publisher = item.get('publisher', '') or item.get('original_publisher', '')
            else:
                name = str(item)
                version = ''
                publisher = ''

            result = self.match_single(name, version, publisher)
            results.append(result)

        print("\n✅ Batch processing complete!\n")
        return results

    def print_stats(self):
        """Print matching statistics"""

        print("=" * 80)
        print("MATCHING STATISTICS")
        print("=" * 80 + "\n")

        total = max(self.stats['total'], 1)

        print(f"Total items processed:       {total}")
        print(f"✅ Successfully matched:     {self.stats['matched']} ({self.stats['matched'] / total * 100:.1f}%)")
        print(f"   ├─ AI verified:           {self.stats['ai_verified']}")
        print(f"   └─ String fallback:       {self.stats['string_fallback']}")
        print(f"❌ Failed to match:          {self.stats['failed']} ({self.stats['failed'] / total * 100:.1f}%)")

        if self.stats['processing_times']:
            avg_time = sum(self.stats['processing_times']) / len(self.stats['processing_times'])
            print(f"\n⏱️  Average processing time:  {avg_time:.2f}ms per item")

        if self.ai:
            self.ai.print_usage_stats()



# ============================================================================
# PRODUCT STATUS MARKDOWN
# ============================================================================

from pathlib import Path
from typing import List, Dict

from pathlib import Path
from typing import List, Dict

def write_product_status_report(final_entries: List[Dict], output_path: Path) -> None:
    """
    Writes a simple text report:

    Matched
    Product Name | Matched With | AI Reason
    ...

    Unmatched
    Product Name
    ...
    """

    def clean(text) -> str:
        return str(text or "").replace("\n", " ").strip()

    # Split entries
    matched = [e for e in final_entries if e.get("matched")]
    unmatched = [e for e in final_entries if not e.get("matched")]

    lines: List[str] = []

    # ----------------- Matched -----------------
    lines.append("Matched")
    if matched:
        lines.append("Product Name | Matched With | AI Reason")
        for e in matched:
            product_name = clean(e.get("original_name"))
            # Prefer canonical; fall back to vendor/product combo
            canonical = clean(e.get("matched_with_canonical")) or \
                        clean(f"{e.get('matched_vendor', '')}/{e.get('matched_product', '')}")
            reason = clean(e.get("ai_reasoning"))
            lines.append(f"{product_name} | {canonical} | {reason}")
    else:
        lines.append("None")

    lines.append("")  # blank line

    # ----------------- Unmatched -----------------
    lines.append("Unmatched")
    if unmatched:
        lines.append("Product Name")
        for e in unmatched:
            product_name = clean(e.get("original_name"))
            lines.append(product_name)
    else:
        lines.append("None")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))



# ============================================================================
# SAVE RESULTS
# ============================================================================

def save_results(results: List[Dict], matcher: HybridMatcher, audit_filename: str):
    """Save results with complete transparency and final flattened JSON."""

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_name = Path(audit_filename).stem

    # ---------- Detailed JSON (full pipeline trace) ----------
    output = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'audit_source': audit_filename,
            'total_items': len(results),
            'database_size': len(matcher.db_products),
            'configuration': {
                'top_k_token_sort': Config.TOP_K_TOKEN_SORT,
                'top_k_partial_ratio': Config.TOP_K_PARTIAL_RATIO,
                'confidence_threshold': Config.CONFIDENCE_THRESHOLD,
                'ollama_model': Config.OLLAMA_MODEL,
            },
        },
        'statistics': matcher.stats,
        'results': results,
    }

    detailed_path = Config.OUTPUT_DIR / 'detailed_results' / f'{base_name}_{timestamp}_detailed.json'
    os.makedirs(detailed_path.parent, exist_ok=True)

    with open(detailed_path, 'w', encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"💾 Detailed results: {detailed_path}")

    # ---------- Transparent log (sample + pointer) ----------
    log_path = Config.LOGS_DIR / f'{base_name}_{timestamp}_transparent.json'
    os.makedirs(log_path.parent, exist_ok=True)

    transparent_log = {
        'summary': {
            'total_processed': len(results),
            'matched': matcher.stats['matched'],
            'failed': matcher.stats['failed'],
            'match_rate': f"{(matcher.stats['matched'] / max(len(results), 1)) * 100:.1f}%",
        },
        'sample_results': results[:10],
        'full_results_location': str(detailed_path),
    }

    with open(log_path, 'w', encoding="utf-8") as f:
        json.dump(transparent_log, f, indent=2)

    print(f"💾 Transparent log:  {log_path}")

    # ---------- CSV summary (for quick analysis) ----------
    csv_data = []
    for r in results:
        verification_info = r.get('stage2_gemini_verification') or {}
        ai_model = verification_info.get('ai_model')
        from_cache = verification_info.get('from_cache', False)
        fallback_used = verification_info.get('fallback_used', False)

        ai_verified = bool(ai_model) and not fallback_used

        csv_data.append({
            'original_name': r.get('original_name', ''),
            'matched': r.get('matched', False),
            'final_vendor': r.get('final_vendor', ''),
            'final_product': r.get('final_product', ''),
            'confidence': r.get('final_confidence', 0.0),
            'ai_verified': ai_verified,
            'ai_model': ai_model,
            'ai_from_cache': from_cache,
            'ai_fallback_used': fallback_used,
        })

    csv_path = Config.OUTPUT_DIR / 'statistics' / f'{base_name}_{timestamp}_summary.csv'
    os.makedirs(csv_path.parent, exist_ok=True)

    pd.DataFrame(csv_data).to_csv(csv_path, index=False)
    print(f"💾 CSV summary:      {csv_path}")

    # ---------- FINAL FLATTENED JSON (for reporting / PDF later) ----------
    os.makedirs(Config.FINAL_DIR, exist_ok=True)
    final_entries = []

    for idx, r in enumerate(results, start=1):
        verification_info = r.get('stage2_gemini_verification') or {}
        entry = {
            "product_number": idx,
            "original_name": r.get('original_name', ''),
            "original_version": r.get('original_version', ''),
            "original_publisher": r.get('original_publisher', ''),
            "matched": bool(r.get('matched', False)),
            "matched_with_canonical": r.get('final_canonical', '') or "",
            "matched_vendor": r.get('final_vendor', '') or "",
            "matched_product": r.get('final_product', '') or "",
            "confidence": float(r.get('final_confidence', 0.0)),
            "ai_model": verification_info.get('ai_model', Config.OLLAMA_MODEL),
            "ai_from_cache": bool(verification_info.get('from_cache', False)),
            "ai_fallback_used": bool(verification_info.get('fallback_used', False)),
            "ai_reasoning": verification_info.get('reasoning', ''),
        }
        final_entries.append(entry)

    final_payload = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "audit_source": audit_filename,
            "total_items": len(results),
            "database_size": len(matcher.db_products),
            "configuration": {
                "confidence_threshold": Config.CONFIDENCE_THRESHOLD,
                "ollama_model": Config.OLLAMA_MODEL,
            },
            "linked_files": {
                "detailed_results": str(detailed_path),
                "transparent_log": str(log_path),
                "csv_summary": str(csv_path),
            },
        },
        "statistics": matcher.stats,
        "entries": final_entries,
    }

    final_json_path = Config.FINAL_DIR / f"{base_name}_{timestamp}_final.json"
    with open(final_json_path, "w", encoding="utf-8") as f:
        json.dump(final_payload, f, indent=2)

    print(f"📦 Final matching JSON: {final_json_path}")

    # ---------- PRODUCT STATUS MARKDOWN (matched / not matched tables) ----------
       # ---------- PRODUCT STATUS TEXT (Matched / Unmatched lists) ----------
    product_status_dir = Config.OUTPUT_DIR / "product_status"
    product_status_path = product_status_dir / f"{base_name}_{timestamp}_product_status.txt"

    write_product_status_report(final_entries, product_status_path)
    print(f"📄 Product status text: {product_status_path}\n")

    return detailed_path, log_path, csv_path, final_json_path



# ============================================================================
# MAIN
# ============================================================================

def main(audit_file: str):
    """Main execution pipeline"""

    print("Starting ZeroWatch CVE Matching Pipeline...\n")

    db_products = load_cve_database()

    if not db_products:
        print("❌ Cannot proceed without database")
        return

    print(f"📂 Loading audit data: {audit_file}")

    with open(audit_file, encoding="utf-8") as f:
        audit_data = json.load(f)

    print(f"✅ Loaded {len(audit_data)} software items\n")

    matcher = HybridMatcher(db_products)

    print("=" * 80)
    print("STARTING HYBRID MATCHING PIPELINE")
    print("=" * 80 + "\n")

    start_time = time.time()
    results = matcher.batch_match(audit_data)
    duration = time.time() - start_time

    matcher.print_stats()

    print(f"\n⏱️  Total pipeline time: {duration:.2f}s")

    print("\n" + "=" * 80)
    print("SAVING RESULTS")
    print("=" * 80 + "\n")

    save_results(results, matcher, audit_file)

    print("\n" + "=" * 80)
    print("PIPELINE COMPLETE!")
    print("=" * 80)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scripts/hybrid_matcher.py <audit_file.json>")
        print("\nExample:")
        print("  python scripts/hybrid_matcher.py input/audit_jsons/aryan_audit.json")
        sys.exit(1)

    audit_file = sys.argv[1]

    if not os.path.exists(audit_file):
        print(f"❌ File not found: {audit_file}")
        sys.exit(1)

    main(audit_file)
