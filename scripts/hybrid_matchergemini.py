

"""
ZEROWATCH CVE MATCHING - HYBRID SYSTEM
Transparent 2-Stage Pipeline: String Matching → Gemini Verification
"""

import json
import os
import time
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import hashlib

import google.generativeai as genai
import pandas as pd
from rapidfuzz import fuzz, process
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

print("=" * 80)
print("ZEROWATCH HYBRID CVE MATCHING SYSTEM")
print("Stage 1: String Matching (Token Sort + Partial Ratio)")
print("Stage 2: Gemini AI Verification")
print("=" * 80 + "\n")


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Configuration from environment"""

    # Matching parameters
    TOP_K_TOKEN_SORT = int(os.getenv('TOP_K_TOKEN_SORT', '10'))
    TOP_K_PARTIAL_RATIO = int(os.getenv('TOP_K_PARTIAL_RATIO', '10'))
    CONFIDENCE_THRESHOLD = float(os.getenv('CONFIDENCE_THRESHOLD', '0.6'))
    # Optional limits to avoid burning keys in one run
    MAX_GEMINI_CALLS = int(os.getenv('MAX_GEMINI_CALLS', '300'))      # global per run
    MAX_CALLS_PER_KEY = int(os.getenv('MAX_CALLS_PER_KEY', '20'))     # per key per run

    # Paths
    PROJECT_ROOT = Path(__file__).parent.parent
    DATA_DIR = PROJECT_ROOT / 'data'
    OUTPUT_DIR = PROJECT_ROOT / 'output'
    LOGS_DIR = OUTPUT_DIR / 'transparent_logs'
    GEMINI_CACHE_PATH = OUTPUT_DIR / 'gemini_cache.jsonl'
    
    @staticmethod
    def load_api_keys() -> Dict[str, str]:
        """Load Gemini API keys from environment"""
        keys: Dict[str, str] = {}

        # Load team member configuration
        config_path = Config.PROJECT_ROOT / 'config' / 'api_keys.json'

        if config_path.exists():
            with open(config_path, encoding="utf-8") as f:
                team_config = json.load(f)

            for member_id, member_info in team_config.get('team_members', {}).items():
                if member_info.get('active', False):
                    env_var = member_info.get('key_env_var')
                    if not env_var:
                        continue
                    key = os.getenv(env_var)
                    if key:
                        keys[member_info['name']] = key
                        print(f"✅ Loaded API key: {member_info['name']}")
        else:
            # Fallback: load all GEMINI_KEY_* variables
            for key, value in os.environ.items():
                if key.startswith('GEMINI_KEY_') and value:
                    member_name = key.replace('GEMINI_KEY_', '').title()
                    keys[member_name] = value
                    print(f"✅ Loaded API key: {member_name}")

        if not keys:
            print("⚠️  WARNING: No Gemini API keys found!")
            print("   Add keys to .env file with format: GEMINI_KEY_NAME=your_key")

        print(f"\n📊 Total API keys loaded: {len(keys)}\n")
        return keys


# ============================================================================
# LOAD DATABASE
# ============================================================================

def load_cve_database(csv_path: Optional[str] = None) -> List[Dict]:
    """Load CPE products database"""

    if not csv_path:
        csv_path = Config.DATA_DIR / 'products_export.csv'

    print(f"📂 Loading CVE database: {csv_path}")

    if not os.path.exists(csv_path):
        print(f"❌ ERROR: Database not found at {csv_path}")
        print("   Please copy product_exports.csv to data/ directory")
        return []

    df = pd.read_csv(csv_path)

    # Auto-detect vendor/product columns
    vendor_candidates = [c for c in df.columns if 'vendor' in c.lower()]
    product_candidates = [c for c in df.columns if 'product' in c.lower()]

    if not vendor_candidates or not product_candidates:
        raise ValueError(
            f"Could not auto-detect vendor/product columns in {csv_path}. "
            f"Columns found: {list(df.columns)}"
        )

    vendor_col = vendor_candidates[0]
    product_col = product_candidates[0]

    print(f"   Detected columns: {vendor_col}, {product_col}")

    products: List[Dict] = []
    for _, row in df.iterrows():
        vendor = str(row[vendor_col]).lower().strip()
        product = str(row[product_col]).lower().strip()

        if vendor and product and vendor != "nan" and product != "nan":
            products.append({
                'vendor': vendor,
                'product': product,
                'canonical': f"{vendor}/{product}",
                'search_text': f"{vendor} {product}",
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
    """Normalize software name by removing noise"""
    name = str(name).lower()

    for pattern in _NOISE_PATTERNS:
        name = pattern.sub('', name)

    return ' '.join(name.split()).strip()


# ============================================================================
# STAGE 1: STRING MATCHING (TRANSPARENT)
# ============================================================================

# ============================================================================
# STAGE 1: STRING MATCHING (TRANSPARENT, WITH SHORT-NAME SAFETY)
# ============================================================================

# Helper: check if a short query actually appears as a full token
def _is_valid_short_match(query: str, matched_text: str) -> bool:
    """
    For very short queries (like 'git', 'go', 'pip'), avoid matches that only
    occur as substrings inside bigger words (e.g. 'digital').

    - For len(query) <= 3 → require that query is a full token in matched_text.
    - For longer queries → always allow (we trust the fuzzy score more).
    """
    q = str(query).strip().lower()
    if not q:
        return False

    # Only apply strict logic for tiny strings
    if len(q) <= 3:
        # Split on non-alphanumeric so 'digital-4.5.10' → ['digital', '4', '5', '10']
        tokens = re.split(r'[^a-z0-9]+', matched_text.lower())
        tokens = [t for t in tokens if t]  # drop empties
        return q in tokens

    return True


def get_candidates_token_sort(
    query: str,
    search_texts: List[str],
    db_products: List[Dict],
    top_k: int
) -> List[Dict]:
    """Get top K candidates using Token Sort Ratio, with short-name safety."""

    matches = process.extract(
        query,
        search_texts,
        scorer=fuzz.token_sort_ratio,
        limit=top_k * 3  # over-sample, we will filter
    )

    candidates: List[Dict] = []
    for matched_text, score, idx in matches:
        # Filter out bad matches for very short queries
        if not _is_valid_short_match(query, matched_text):
            continue

        product = db_products[idx]
        candidates.append({
            'vendor': product['vendor'],
            'product': product['product'],
            'version': product.get('version'),
            'canonical': product['canonical'],
            'score': score / 100.0,
            'method': 'token_sort',
            'matched_text': matched_text,
        })

        if len(candidates) >= top_k:
            break

    return candidates


def get_candidates_partial_ratio(
    query: str,
    search_texts: List[str],
    db_products: List[Dict],
    top_k: int
) -> List[Dict]:
    """Get top K candidates using Partial Ratio, with short-name safety."""

    matches = process.extract(
        query,
        search_texts,
        scorer=fuzz.partial_ratio,
        limit=top_k * 3  # over-sample, we will filter
    )

    candidates: List[Dict] = []
    for matched_text, score, idx in matches:
        # Filter out bad matches for very short queries
        if not _is_valid_short_match(query, matched_text):
            continue

        product = db_products[idx]
        candidates.append({
            'vendor': product['vendor'],
            'product': product['product'],
            'version': product.get('version'),
            'canonical': product['canonical'],
            'score': score / 100.0,
            'method': 'partial_ratio',
            'matched_text': matched_text,
        })

        if len(candidates) >= top_k:
            break

    return candidates


def get_all_candidates(
    query: str,
    db_products: List[Dict],
    search_texts: List[str]
) -> Dict:
    """
    STAGE 1: Get candidates from BOTH algorithms.
    Returns transparent structure showing all candidates.
    """

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
# STAGE 2: GEMINI VERIFICATION (TRANSPARENT)
# ============================================================================

class GeminiVerifier:
    """Transparent Gemini verification with:
    - persistent caching
    - round-robin API key usage
    - automatic disabling of exhausted keys
    - per-run call limits
    """

    def __init__(self, api_keys: Dict[str, str]):
        self.api_keys = api_keys
        self.member_names: List[str] = list(api_keys.keys())
        self.current_idx: int = 0

        self.usage_stats: Dict[str, int] = {name: 0 for name in self.member_names}
        self.exhausted: Dict[str, bool] = {name: False for name in self.member_names}
        self.total_calls: int = 0

        # ---- Cache setup ----
        self.cache_path = Config.GEMINI_CACHE_PATH
        self.cache: Dict[str, Dict] = {}
        self._load_cache()

        if self.member_names:
            print(f"✅ Initialized Gemini with {len(self.member_names)} API keys\n")
        else:
            print("⚠️  GeminiVerifier initialized with 0 API keys\n")

    # -------------------------
    # CACHE HANDLING
    # -------------------------

    def _load_cache(self):
        """Load cached Gemini decisions from disk (jsonl)."""
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
            print(f"📦 Gemini cache loaded: {len(self.cache)} entries")
        except Exception as e:
            print(f"⚠️  Failed to load Gemini cache: {e}")

    def _make_cache_key(self, original_name: str, candidates: List[Dict]) -> str:
        """
        Build a stable cache key based on:
        - normalized original software name
        - top candidate canonicals (order matters)
        """
        norm_name = str(original_name).strip().lower()
        top_canonicals = [c["canonical"] for c in candidates[:10]]

        payload = {
            "original_name": norm_name,
            "top_candidates": top_canonicals,
        }
        raw = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _get_from_cache(self, cache_key: str) -> Optional[Dict]:
        result = self.cache.get(cache_key)
        if result is None:
            return None
        # Return a copy so we can safely mutate per-run metadata
        return json.loads(json.dumps(result))

    def _save_to_cache(self, cache_key: str, core_result: Dict):
        """Append a new entry to the cache file & in-memory dict."""
        self.cache[cache_key] = core_result
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"key": cache_key, "result": core_result}) + "\n")
        except Exception as e:
            print(f"⚠️  Failed to write Gemini cache entry: {e}")

    # -------------------------
    # KEY MANAGEMENT
    # -------------------------

    def has_available_keys(self) -> bool:
        """Return True if at least one key is not exhausted and global limit not hit."""
        if self.total_calls >= Config.MAX_GEMINI_CALLS:
            return False
        return any(
            not self.exhausted[name]
            and self.usage_stats.get(name, 0) < Config.MAX_CALLS_PER_KEY
            for name in self.member_names
        )

    def _get_next_member(self) -> Tuple[Optional[str], Optional[str]]:
        """Round-robin through non-exhausted team members' API keys."""
        if not self.member_names:
            return None, None

        attempts = 0
        n = len(self.member_names)

        while attempts < n:
            member_name = self.member_names[self.current_idx]
            self.current_idx = (self.current_idx + 1) % n

            if self.exhausted.get(member_name, False):
                attempts += 1
                continue

            if self.usage_stats[member_name] >= Config.MAX_CALLS_PER_KEY:
                self.exhausted[member_name] = True
                attempts += 1
                continue

            api_key = self.api_keys[member_name]
            self.usage_stats[member_name] += 1
            self.total_calls += 1
            return member_name, api_key

            attempts += 1

        return None, None

    # -------------------------
    # UTILITIES
    # -------------------------

    def _strip_code_fences(self, text: str) -> str:
        """Strip ```json ... ``` or ``` ... ``` fences from LLM output safely."""
        if "```" not in text:
            return text.strip()

        parts = text.split("```")
        for segment in parts:
            segment = segment.strip()
            if segment.startswith("{") and segment.endswith("}"):
                return segment
            if "{" in segment and "}" in segment:
                inside = segment[segment.find("{"): segment.rfind("}") + 1]
                if inside.strip().startswith("{"):
                    return inside.strip()

        return text.strip()

    # -------------------------
    # MAIN CALL
    # -------------------------

    def verify_match(self, original_name: str, candidates: List[Dict]) -> Dict:
        """Ask Gemini to select best match from candidates, with cache + limits."""

        # ----- CACHE CHECK -----
        cache_key = self._make_cache_key(original_name, candidates)
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            # enrich cached result with run-specific metadata
            cached["from_cache"] = True
            cached.setdefault("total_candidates_provided", len(candidates))
            cached.setdefault("gemini_api_key_owner", cached.get("gemini_api_key_owner", "cache"))
            cached.setdefault("gemini_response_time_ms", 0)
            return cached

        # ----- PROMPT -----
        candidates_lines = []
        for i, candidate in enumerate(candidates[:20], 1):
            cand_line = (
                f"{i}. {candidate['canonical']} "
                f"(score: {candidate['score']:.2%}, method: {candidate['method']})"
            )
            candidates_lines.append(cand_line)
        candidates_text = "\n".join(candidates_lines)

        prompt_template = """You are a software product matching expert for cybersecurity CVE auditing.

TASK: Match the installed software to the correct CVE database product.

INSTALLED SOFTWARE:
"{original}"

CANDIDATE MATCHES FROM DATABASE (scored by string similarity):
{candidates}

INSTRUCTIONS:
1. Analyze the original software name carefully
2. Compare against all candidates
3. Select the SINGLE BEST match
4. If NO candidate matches confidently, return "NO_MATCH"

RESPOND IN EXACTLY THIS JSON FORMAT:
{{
  "matched": true,
  "selected_canonical": "vendor/product",
  "confidence": 0.95,
  "reasoning": "Brief explanation",
  "alternatives_considered": ["vendor2/product2"]
}}

OR if no match:
{{
  "matched": false,
  "reasoning": "Why none match"
}}

JSON response:"""

        prompt = prompt_template.format(
            original=original_name,
            candidates=candidates_text
        )

        # If overall or per-key limits are hit, don't call Gemini, use fallback
        if not self.has_available_keys():
            best = candidates[0]
            core = {
                "matched": True,
                "selected_canonical": best["canonical"],
                "vendor": best["vendor"],
                "product": best["product"],
                "confidence": best["score"],
                "reasoning": "Gemini call limit reached for this run, using highest string match",
            }
            core["gemini_api_key_owner"] = "fallback_limit"
            core["gemini_response_time_ms"] = 0
            core["total_candidates_provided"] = len(candidates)
            core["fallback_used"] = True

            # still save in cache so repeated items in this run don't recompute
            self._save_to_cache(cache_key, core)
            return core

        member_name = None

        try:
            member_name, api_key = self._get_next_member()
            if not api_key:
                # no active keys available
                best = candidates[0]
                core = {
                    "matched": True,
                    "selected_canonical": best["canonical"],
                    "vendor": best["vendor"],
                    "product": best["product"],
                    "confidence": best["score"],
                    "reasoning": "No available Gemini keys, using highest string match",
                }
                core["gemini_api_key_owner"] = "fallback_no_keys"
                core["gemini_response_time_ms"] = 0
                core["total_candidates_provided"] = len(candidates)
                core["fallback_used"] = True
                self._save_to_cache(cache_key, core)
                return core

            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-2.0-flash-exp")

            start_time = time.time()
            response = model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=400
                )
            )
            gemini_time = time.time() - start_time

            text = (response.text or "").strip()
            text = self._strip_code_fences(text)

            parsed = json.loads(text)

            # enrich core result
            core = dict(parsed)  # shallow copy
            core["gemini_api_key_owner"] = member_name
            core["gemini_response_time_ms"] = round(gemini_time * 1000, 2)
            core["gemini_raw_response"] = text[:500]
            core["total_candidates_provided"] = len(candidates)

            if core.get("matched"):
                canonical = core.get("selected_canonical", "")
                if "/" in canonical:
                    vendor, product = canonical.split("/", 1)
                    core["vendor"] = vendor
                    core["product"] = product

            # Save to cache (this is the heavy call you don't want to repeat)
            self._save_to_cache(cache_key, core)
            return core

        except Exception as e:
            msg = str(e)
            print(f"⚠️  Gemini verification failed: {msg[:150]}")

            # If quota exceeded for this key, mark it exhausted so we stop using it
            if member_name and ("429" in msg or "quota" in msg.lower()):
                self.exhausted[member_name] = True

            best = candidates[0]
            core = {
                "matched": True,
                "selected_canonical": best["canonical"],
                "vendor": best["vendor"],
                "product": best["product"],
                "confidence": best["score"],
                "reasoning": "Gemini unavailable or quota exceeded, using highest string match",
            }
            core["gemini_api_key_owner"] = member_name or "fallback_error"
            core["gemini_response_time_ms"] = 0
            core["total_candidates_provided"] = len(candidates)
            core["fallback_used"] = True

            # cache this fallback too
            self._save_to_cache(cache_key, core)
            return core

    def print_usage_stats(self):
        """Print API key usage statistics"""

        print("\n" + "=" * 80)
        print("GEMINI API KEY USAGE STATISTICS")
        print("=" * 80 + "\n")

        for member, count in self.usage_stats.items():
            exhausted = " (exhausted)" if self.exhausted.get(member) else ""
            print(f"  {member:20s}: {count:4d} requests{exhausted}")

        print(f"\n  Total calls this run: {self.total_calls}")



# ============================================================================
# HYBRID MATCHER (MAIN PIPELINE)
# ============================================================================

class HybridMatcher:
    """Complete transparent hybrid matching pipeline"""

    def __init__(self, db_products: List[Dict], api_keys: Dict[str, str]):
        self.db_products = db_products
        self.search_texts = [p['search_text'] for p in db_products]
        self.gemini = GeminiVerifier(api_keys) if api_keys else None

        self.stats = {
            'total': 0,
            'matched': 0,
            'gemini_verified': 0,
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

        # Stage 2: Gemini verification (if available)
        if self.gemini:
            gemini_raw_result = self.gemini.verify_match(
                software_name,
                stage1_result['combined_unique']
            )

            # Enforce global confidence threshold
            gemini_result = self._apply_confidence_threshold({
                **gemini_raw_result
            })

            matched_flag = gemini_result.get('matched', False)

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
                'stage2_gemini_verification': gemini_result,
                'matched': matched_flag,
                'final_vendor': gemini_result.get('vendor'),
                'final_product': gemini_result.get('product'),
                'final_canonical': gemini_result.get('selected_canonical'),
                'final_confidence': gemini_result.get('confidence', 0.0),
                'total_processing_time_ms': round((time.time() - start_time) * 1000, 2),
                'timestamp': datetime.now().isoformat(),
            }

            if matched_flag:
                self.stats['matched'] += 1
                if gemini_result.get('fallback_used'):
                    self.stats['string_fallback'] += 1
                else:
                    self.stats['gemini_verified'] += 1
            else:
                self.stats['failed'] += 1

        else:
            # No Gemini - use best string match
            best = stage1_result['combined_unique'][0]
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
                'stage2_gemini_verification': {
                    'status': 'skipped',
                    'reason': 'Gemini API not configured',
                },
                'matched': True,
                'final_vendor': best['vendor'],
                'final_product': best['product'],
                'final_canonical': best['canonical'],
                'final_confidence': best['score'],
                'total_processing_time_ms': round((time.time() - start_time) * 1000, 2),
                'timestamp': datetime.now().isoformat(),
            }

            self.stats['matched'] += 1
            self.stats['string_fallback'] += 1

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
                publisher = item.get('publisher', '')
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
        print(f"   ├─ Gemini verified:       {self.stats['gemini_verified']}")
        print(f"   └─ String fallback:       {self.stats['string_fallback']}")
        print(f"❌ Failed to match:          {self.stats['failed']} ({self.stats['failed'] / total * 100:.1f}%)")

        if self.stats['processing_times']:
            avg_time = sum(self.stats['processing_times']) / len(self.stats['processing_times'])
            print(f"\n⏱️  Average processing time:  {avg_time:.2f}ms per item")

        if self.gemini:
            self.gemini.print_usage_stats()


# ============================================================================
# SAVE RESULTS
# ============================================================================

def save_results(results: List[Dict], matcher: HybridMatcher, audit_filename: str):
    """Save results with complete transparency"""

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_name = Path(audit_filename).stem

    output = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'audit_source': audit_filename,
            'total_items': len(results),
            'database_size': len(matcher.db_products),
            'gemini_keys_configured': len(matcher.gemini.api_keys) if matcher.gemini else 0,
            'configuration': {
                'top_k_token_sort': Config.TOP_K_TOKEN_SORT,
                'top_k_partial_ratio': Config.TOP_K_PARTIAL_RATIO,
                'confidence_threshold': Config.CONFIDENCE_THRESHOLD,
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

    csv_data = []
    for r in results:
        verification_info = r.get('stage2_gemini_verification') or {}
        gemini_owner = verification_info.get('gemini_api_key_owner')
        status = verification_info.get('status')

        gemini_verified = (
            gemini_owner not in (None, 'fallback')
            and status != 'skipped'
        )

        csv_data.append({
            'original_name': r.get('original_name', ''),
            'matched': r.get('matched', False),
            'final_vendor': r.get('final_vendor', ''),
            'final_product': r.get('final_product', ''),
            'confidence': r.get('final_confidence', 0.0),
            'gemini_verified': gemini_verified,
        })

    csv_path = Config.OUTPUT_DIR / 'statistics' / f'{base_name}_{timestamp}_summary.csv'
    os.makedirs(csv_path.parent, exist_ok=True)

    pd.DataFrame(csv_data).to_csv(csv_path, index=False)
    print(f"💾 CSV summary:      {csv_path}\n")

    return detailed_path, log_path, csv_path


# ============================================================================
# MAIN
# ============================================================================

def main(audit_file: str):
    """Main execution pipeline"""

    print("Starting ZeroWatch CVE Matching Pipeline...\n")

    api_keys = Config.load_api_keys()
    db_products = load_cve_database()

    if not db_products:
        print("❌ Cannot proceed without database")
        return

    print(f"📂 Loading audit data: {audit_file}")

    with open(audit_file, encoding="utf-8") as f:
        audit_data = json.load(f)

    print(f"✅ Loaded {len(audit_data)} software items\n")

    matcher = HybridMatcher(db_products, api_keys)

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
        print("Usage: python 02_hybrid_matcher.py <audit_file.json>")
        print("\nExample:")
        print("  python scripts/02_hybrid_matcher.py input/audit_jsons/aryan_audit.json")
        sys.exit(1)

    audit_file = sys.argv[1]

    if not os.path.exists(audit_file):
        print(f"❌ File not found: {audit_file}")
        sys.exit(1)

    main(audit_file)
