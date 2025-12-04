# # FILE: scripts/02_hybrid_matcher.py

# """
# ZEROWATCH CVE MATCHING - HYBRID SYSTEM
# Transparent 2-Stage Pipeline: String Matching → Gemini Verification
# """

# import json
# import pandas as pd
# from rapidfuzz import fuzz, process
# import google.generativeai as genai
# import time
# from typing import List, Dict, Optional
# import os
# from datetime import datetime
# from dotenv import load_dotenv
# from pathlib import Path

# # Load environment variables
# load_dotenv()

# print("="*80)
# print("ZEROWATCH HYBRID CVE MATCHING SYSTEM")
# print("Stage 1: String Matching (Token Sort + Partial Ratio)")
# print("Stage 2: Gemini AI Verification")
# print("="*80 + "\n")

# # ============================================================================
# # CONFIGURATION
# # ============================================================================

# class Config:
#     """Configuration from environment"""
    
#     # Matching parameters
#     TOP_K_TOKEN_SORT = int(os.getenv('TOP_K_TOKEN_SORT', '10'))
#     TOP_K_PARTIAL_RATIO = int(os.getenv('TOP_K_PARTIAL_RATIO', '10'))
#     CONFIDENCE_THRESHOLD = float(os.getenv('CONFIDENCE_THRESHOLD', '0.6'))
    
#     # Paths
#     PROJECT_ROOT = Path(__file__).parent.parent
#     DATA_DIR = PROJECT_ROOT / 'data'
#     OUTPUT_DIR = PROJECT_ROOT / 'output'
#     LOGS_DIR = OUTPUT_DIR / 'transparent_logs'
    
#     @staticmethod
#     def load_api_keys() -> dict:
#         """Load Gemini API keys from environment"""
#         keys = {}
        
#         # Load team member configuration
#         config_path = Config.PROJECT_ROOT / 'config' / 'api_keys.json'
        
#         if config_path.exists():
#             with open(config_path) as f:
#                 team_config = json.load(f)
            
#             for member_id, member_info in team_config['team_members'].items():
#                 if member_info.get('active', False):
#                     env_var = member_info['key_env_var']
#                     key = os.getenv(env_var)
                    
#                     if key:
#                         keys[member_info['name']] = key
#                         print(f"✅ Loaded API key: {member_info['name']}")
#         else:
#             # Fallback: load all GEMINI_KEY_* variables
#             for key, value in os.environ.items():
#                 if key.startswith('GEMINI_KEY_') and value:
#                     member_name = key.replace('GEMINI_KEY_', '').title()
#                     keys[member_name] = value
#                     print(f"✅ Loaded API key: {member_name}")
        
#         if not keys:
#             print("⚠️  WARNING: No Gemini API keys found!")
#             print("   Add keys to .env file with format: GEMINI_KEY_NAME=your_key")
        
#         print(f"\n📊 Total API keys loaded: {len(keys)}\n")
        
#         return keys


# # ============================================================================
# # LOAD DATABASE
# # ============================================================================

# def load_cve_database(csv_path: Optional[str] = None) -> List[Dict]:
#     """Load CPE products database"""
    
#     if not csv_path:
#         csv_path = Config.DATA_DIR / 'products_export.csv'
    
#     print(f"📂 Loading CVE database: {csv_path}")
    
#     if not os.path.exists(csv_path):
#         print(f"❌ ERROR: Database not found at {csv_path}")
#         print("   Please copy product_exports.csv to data/ directory")
#         return []
    
#     df = pd.read_csv(csv_path)
    
#     # Auto-detect columns
#     vendor_col = [c for c in df.columns if 'vendor' in c.lower()][0]
#     product_col = [c for c in df.columns if 'product' in c.lower()][0]
    
#     print(f"   Detected columns: {vendor_col}, {product_col}")
    
#     products = []
#     for _, row in df.iterrows():
#         vendor = str(row[vendor_col]).lower().strip()
#         product = str(row[product_col]).lower().strip()
        
#         if vendor and product:
#             products.append({
#                 'vendor': vendor,
#                 'product': product,
#                 'canonical': f"{vendor}/{product}",
#                 'search_text': f"{vendor} {product}"
#             })
    
#     print(f"✅ Loaded {len(products):,} products\n")
    
#     return products


# # ============================================================================
# # NORMALIZATION
# # ============================================================================

# def normalize_software_name(name: str) -> str:
#     """Normalize software name by removing noise"""
#     import re
    
#     name = name.lower()
    
#     # Remove common noise patterns
#     patterns = [
#         r'\(64-bit\)', r'\(x64\)', r'\(x86\)', r'\(32-bit\)',
#         r'\bversion\b', r'\bv\d+\.\d+', r'\bx64\b', r'\bx86\b',
#         r'\d+\.\d+\.\d+\.\d+', r'\d+\.\d+\.\d+',
#         r'\(remove only\)', r'\(64 bit\)', r'\(32 bit\)',
#         r'\.exe$', r'\.msi$', r'\.app$',
#         r'\s+update\s+\d+', r'\s+sp\d+',
#         r'microsoft\s+visual\s+c\+\+',
#     ]
    
#     for pattern in patterns:
#         name = re.sub(pattern, '', name, flags=re.IGNORECASE)
    
#     return ' '.join(name.split()).strip()


# # ============================================================================
# # STAGE 1: STRING MATCHING (TRANSPARENT)
# # ============================================================================

# def get_candidates_token_sort(query: str, db_products: List[Dict], top_k: int) -> List[Dict]:
#     """Get top K candidates using Token Sort Ratio"""
    
#     search_texts = [p['search_text'] for p in db_products]
    
#     matches = process.extract(
#         query,
#         search_texts,
#         scorer=fuzz.token_sort_ratio,
#         limit=top_k
#     )
    
#     candidates = []
#     for matched_text, score, idx in matches:
#         product = db_products[idx]
#         candidates.append({
#             'vendor': product['vendor'],
#             'product': product['product'],
#             'canonical': product['canonical'],
#             'score': score / 100,
#             'method': 'token_sort',
#             'matched_text': matched_text
#         })
    
#     return candidates


# def get_candidates_partial_ratio(query: str, db_products: List[Dict], top_k: int) -> List[Dict]:
#     """Get top K candidates using Partial Ratio"""
    
#     search_texts = [p['search_text'] for p in db_products]
    
#     matches = process.extract(
#         query,
#         search_texts,
#         scorer=fuzz.partial_ratio,
#         limit=top_k
#     )
    
#     candidates = []
#     for matched_text, score, idx in matches:
#         product = db_products[idx]
#         candidates.append({
#             'vendor': product['vendor'],
#             'product': product['product'],
#             'canonical': product['canonical'],
#             'score': score / 100,
#             'method': 'partial_ratio',
#             'matched_text': matched_text
#         })
    
#     return candidates


# def get_all_candidates(query: str, db_products: List[Dict]) -> Dict:
#     """
#     STAGE 1: Get candidates from BOTH algorithms
#     Returns transparent structure showing all candidates
#     """
    
#     # Get top K from each algorithm
#     token_sort_candidates = get_candidates_token_sort(
#         query, db_products, Config.TOP_K_TOKEN_SORT
#     )
    
#     partial_ratio_candidates = get_candidates_partial_ratio(
#         query, db_products, Config.TOP_K_PARTIAL_RATIO
#     )
    
#     # Combine and deduplicate
#     all_candidates = {}
    
#     for candidate in token_sort_candidates + partial_ratio_candidates:
#         key = candidate['canonical']
        
#         if key not in all_candidates:
#             all_candidates[key] = candidate
#         else:
#             # Keep higher score
#             if candidate['score'] > all_candidates[key]['score']:
#                 all_candidates[key] = candidate
    
#     # Sort by score
#     sorted_candidates = sorted(
#         all_candidates.values(),
#         key=lambda x: x['score'],
#         reverse=True
#     )
    
#     return {
#         'token_sort_top10': token_sort_candidates,
#         'partial_ratio_top10': partial_ratio_candidates,
#         'combined_unique': sorted_candidates,
#         'total_unique_candidates': len(sorted_candidates)
#     }


# # ============================================================================
# # STAGE 2: GEMINI VERIFICATION (TRANSPARENT)
# # ============================================================================

# class GeminiVerifier:
#     """Transparent Gemini verification with round-robin API key usage"""
    
#     def __init__(self, api_keys: Dict[str, str]):
#         self.api_keys = api_keys
#         self.member_names = list(api_keys.keys())
#         self.current_idx = 0
#         self.usage_stats = {name: 0 for name in self.member_names}
        
#         # Initialize models
#         self.models = {}
#         for name, key in api_keys.items():
#             genai.configure(api_key=key)
#             self.models[name] = genai.GenerativeModel('gemini-2.0-flash-exp')
        
#         print(f"✅ Initialized Gemini with {len(self.models)} API keys\n")
    
#     def get_next_model(self) -> tuple:
#         """Round-robin through team members' API keys"""
        
#         if not self.member_names:
#             return None, None
        
#         member_name = self.member_names[self.current_idx]
#         model = self.models[member_name]
        
#         self.usage_stats[member_name] += 1
#         self.current_idx = (self.current_idx + 1) % len(self.member_names)
        
#         return member_name, model
    
#     def verify_match(self, original_name: str, candidates: List[Dict]) -> Dict:
#         """Ask Gemini to select best match from candidates"""
        
#         # Build candidates list
#         candidates_text = ""
#         for i, candidate in enumerate(candidates[:20], 1):
#             cand_line = "{0}. {1} (score: {2:.2%}, method: {3})\n".format(
#                 i, 
#                 candidate['canonical'], 
#                 candidate['score'], 
#                 candidate['method']
#             )
#             candidates_text += cand_line
        
#         # Build complete prompt
#         prompt_template = """You are a software product matching expert for cybersecurity CVE auditing.

# TASK: Match the installed software to the correct CVE database product.

# INSTALLED SOFTWARE:
# "{original}"

# CANDIDATE MATCHES FROM DATABASE (scored by string similarity):
# {candidates}

# INSTRUCTIONS:
# 1. Analyze the original software name carefully
# 2. Compare against all candidates
# 3. Select the SINGLE BEST match
# 4. If NO candidate matches confidently, return "NO_MATCH"

# RESPOND IN EXACTLY THIS JSON FORMAT:
# {{
#   "matched": true,
#   "selected_canonical": "vendor/product",
#   "confidence": 0.95,
#   "reasoning": "Brief explanation",
#   "alternatives_considered": ["vendor2/product2"]
# }}

# OR if no match:
# {{
#   "matched": false,
#   "reasoning": "Why none match"
# }}

# JSON response:"""
        
#         prompt = prompt_template.format(
#             original=original_name,
#             candidates=candidates_text
#         )
        
#         try:
#             member_name, model = self.get_next_model()
            
#             if not model:
#                 raise Exception("No Gemini API keys available")
            
#             start_time = time.time()
            
#             response = model.generate_content(
#                 prompt,
#                 generation_config=genai.GenerationConfig(
#                     temperature=0.1,
#                     max_output_tokens=400
#                 )
#             )
            
#             gemini_time = time.time() - start_time
            
#             text = response.text.strip()
            
#             # Parse JSON - handle markdown code blocks
#             if ('```')[0]:
#                 parts = text.split('```json')
#                 if len(parts) > 1:
#                     text = parts[1].split('```')[0]
#             elif '```' in text:
#                 parts = text.split('```')[0]
#                 if len(parts) > 1:
#                     text = parts.split('```')[0]
            
#             result = json.loads(text.strip())
            
#             # Add transparency metadata
#             result['gemini_api_key_owner'] = member_name
#             result['gemini_response_time_ms'] = round(gemini_time * 1000, 2)
#             result['gemini_raw_response'] = text[:500]
#             result['total_candidates_provided'] = len(candidates)
            
#             # Parse canonical if matched
#             if result.get('matched'):
#                 canonical = result.get('selected_canonical', '')
#                 if '/' in canonical:
#                     parts = canonical.split('/', 1)
#                     result['vendor'] = parts[0]
#                     result['product'] = parts[1]
            
#             return result
        
#         except Exception as e:
#             print(f"⚠️  Gemini verification failed: {str(e)[:100]}")
            
#             # Fallback: use highest string match
#             best = candidates[0]
            
#             return {
#                 'matched': True,
#                 'selected_canonical': best['canonical'],
#                 'vendor': best['vendor'],
#                 'product': best['product'],
#                 'confidence': best['score'],
#                 'reasoning': 'Gemini unavailable, using highest string match',
#                 'gemini_api_key_owner': 'fallback',
#                 'gemini_response_time_ms': 0,
#                 'total_candidates_provided': len(candidates),
#                 'fallback_used': True
#             }
    
#     def print_usage_stats(self):
#         """Print API key usage statistics"""
        
#         print("\n" + "="*80)
#         print("GEMINI API KEY USAGE STATISTICS")
#         print("="*80 + "\n")
        
#         for member, count in self.usage_stats.items():
#             print(f"  {member:20s}: {count:4d} requests")
        
#         total = sum(self.usage_stats.values())
#         print(f"\n  Total: {total} requests")


# # ============================================================================
# # HYBRID MATCHER (MAIN PIPELINE)
# # ============================================================================

# class HybridMatcher:
#     """Complete transparent hybrid matching pipeline"""
    
#     def __init__(self, db_products: List[Dict], api_keys: Dict[str, str]):
#         self.db_products = db_products
#         self.gemini = GeminiVerifier(api_keys) if api_keys else None
        
#         self.stats = {
#             'total': 0,
#             'matched': 0,
#             'gemini_verified': 0,
#             'string_fallback': 0,
#             'failed': 0,
#             'processing_times': []
#         }
    
#     def match_single(self, software_name: str, version: str = '', publisher: str = '') -> Dict:
#         """Complete transparent matching for one software item"""
        
#         self.stats['total'] += 1
#         start_time = time.time()
        
#         # Stage 1: String matching
#         normalized = normalize_software_name(software_name)
#         stage1_result = get_all_candidates(normalized, self.db_products)
        
#         stage1_time = time.time() - start_time
        
#         # Stage 2: Gemini verification
#         if self.gemini and stage1_result['combined_unique']:
#             gemini_result = self.gemini.verify_match(
#                 software_name,
#                 stage1_result['combined_unique']
#             )
            
#             # Build transparent result
#             result = {
#                 'original_name': software_name,
#                 'original_version': version,
#                 'original_publisher': publisher,
#                 'normalized_query': normalized,
#                 'stage1_string_matching': {
#                     'token_sort_top10': stage1_result['token_sort_top10'],
#                     'partial_ratio_top10': stage1_result['partial_ratio_top10'],
#                     'combined_unique_candidates': stage1_result['combined_unique'],
#                     'total_unique': stage1_result['total_unique_candidates'],
#                     'processing_time_ms': round(stage1_time * 1000, 2)
#                 },
#                 'stage2_gemini_verification': gemini_result,
#                 'matched': gemini_result.get('matched', False),
#                 'final_vendor': gemini_result.get('vendor'),
#                 'final_product': gemini_result.get('product'),
#                 'final_canonical': gemini_result.get('selected_canonical'),
#                 'final_confidence': gemini_result.get('confidence', 0),
#                 'total_processing_time_ms': round((time.time() - start_time) * 1000, 2),
#                 'timestamp': datetime.now().isoformat()
#             }
            
#             if gemini_result.get('matched'):
#                 self.stats['matched'] += 1
                
#                 if gemini_result.get('fallback_used'):
#                     self.stats['string_fallback'] += 1
#                 else:
#                     self.stats['gemini_verified'] += 1
#             else:
#                 self.stats['failed'] += 1
        
#         else:
#             # No Gemini - use best string match
#             if stage1_result['combined_unique']:
#                 best = stage1_result['combined_unique'][0]
                
#                 result = {
#                     'original_name': software_name,
#                     'original_version': version,
#                     'original_publisher': publisher,
#                     'normalized_query': normalized,
#                     'stage1_string_matching': {
#                         'token_sort_top10': stage1_result['token_sort_top10'],
#                         'partial_ratio_top10': stage1_result['partial_ratio_top10'],
#                         'combined_unique_candidates': stage1_result['combined_unique'],
#                         'total_unique': stage1_result['total_unique_candidates'],
#                         'processing_time_ms': round(stage1_time * 1000, 2)
#                     },
#                     'stage2_gemini_verification': {
#                         'status': 'skipped',
#                         'reason': 'Gemini API not configured'
#                     },
#                     'matched': True,
#                     'final_vendor': best['vendor'],
#                     'final_product': best['product'],
#                     'final_canonical': best['canonical'],
#                     'final_confidence': best['score'],
#                     'total_processing_time_ms': round((time.time() - start_time) * 1000, 2),
#                     'timestamp': datetime.now().isoformat()
#                 }
                
#                 self.stats['matched'] += 1
#                 self.stats['string_fallback'] += 1
#             else:
#                 result = {
#                     'original_name': software_name,
#                     'matched': False,
#                     'reason': 'no_candidates_found'
#                 }
#                 self.stats['failed'] += 1
        
#         self.stats['processing_times'].append(result.get('total_processing_time_ms', 0))
        
#         return result
    
#     def batch_match(self, software_list: List[Dict]) -> List[Dict]:
#         """Match a batch of software with progress tracking"""
        
#         from tqdm import tqdm
        
#         results = []
        
#         print(f"Processing {len(software_list)} software items...\n")
        
#         for item in tqdm(software_list, desc="Matching", unit="item"):
#             if isinstance(item, dict):
#                 name = item.get('name', '')
#                 version = item.get('version', '')
#                 publisher = item.get('publisher', '')
#             else:
#                 name = str(item)
#                 version = ''
#                 publisher = ''
            
#             result = self.match_single(name, version, publisher)
#             results.append(result)
        
#         print("\n✅ Batch processing complete!\n")
        
#         return results
    
#     def print_stats(self):
#         """Print matching statistics"""
        
#         print("="*80)
#         print("MATCHING STATISTICS")
#         print("="*80 + "\n")
        
#         total = self.stats['total']
        
#         print(f"Total items processed:       {total}")
#         print(f"✅ Successfully matched:     {self.stats['matched']} ({self.stats['matched']/total*100:.1f}%)")
#         print(f"   ├─ Gemini verified:       {self.stats['gemini_verified']}")
#         print(f"   └─ String fallback:       {self.stats['string_fallback']}")
#         print(f"❌ Failed to match:          {self.stats['failed']} ({self.stats['failed']/total*100:.1f}%)")
        
#         if self.stats['processing_times']:
#             avg_time = sum(self.stats['processing_times']) / len(self.stats['processing_times'])
#             print(f"\n⏱️  Average processing time:  {avg_time:.2f}ms per item")
        
#         if self.gemini:
#             self.gemini.print_usage_stats()


# # ============================================================================
# # SAVE RESULTS
# # ============================================================================

# def save_results(results: List[Dict], matcher: HybridMatcher, audit_filename: str):
#     """Save results with complete transparency"""
    
#     timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
#     base_name = Path(audit_filename).stem
    
#     output = {
#         'metadata': {
#             'generated_at': datetime.now().isoformat(),
#             'audit_source': audit_filename,
#             'total_items': len(results),
#             'database_size': len(matcher.db_products),
#             'gemini_keys_configured': len(matcher.gemini.api_keys) if matcher.gemini else 0,
#             'configuration': {
#                 'top_k_token_sort': Config.TOP_K_TOKEN_SORT,
#                 'top_k_partial_ratio': Config.TOP_K_PARTIAL_RATIO,
#                 'confidence_threshold': Config.CONFIDENCE_THRESHOLD
#             }
#         },
#         'statistics': matcher.stats,
#         'results': results
#     }
    
#     detailed_path = Config.OUTPUT_DIR / 'detailed_results' / f'{base_name}_{timestamp}_detailed.json'
#     os.makedirs(detailed_path.parent, exist_ok=True)
    
#     with open(detailed_path, 'w') as f:
#         json.dump(output, f, indent=2)
    
#     print(f"💾 Detailed results: {detailed_path}")
    
#     log_path = Config.LOGS_DIR / f'{base_name}_{timestamp}_transparent.json'
#     os.makedirs(log_path.parent, exist_ok=True)
    
#     transparent_log = {
#         'summary': {
#             'total_processed': len(results),
#             'matched': matcher.stats['matched'],
#             'failed': matcher.stats['failed'],
#             'match_rate': f"{matcher.stats['matched']/len(results)*100:.1f}%"
#         },
#         'sample_results': results[:10],
#         'full_results_location': str(detailed_path)
#     }
    
#     with open(log_path, 'w') as f:
#         json.dump(transparent_log, f, indent=2)
    
#     print(f"💾 Transparent log:  {log_path}")
    
#     csv_data = []
#     for r in results:
#         csv_data.append({
#             'original_name': r.get('original_name', ''),
#             'matched': r.get('matched', False),
#             'final_vendor': r.get('final_vendor', ''),
#             'final_product': r.get('final_product', ''),
#             'confidence': r.get('final_confidence', 0),
#             'gemini_verified': r.get('stage2_gemini_verification', {}).get('gemini_api_key_owner') != 'fallback'
#         })
    
#     csv_path = Config.OUTPUT_DIR / 'statistics' / f'{base_name}_{timestamp}_summary.csv'
#     os.makedirs(csv_path.parent, exist_ok=True)
    
#     pd.DataFrame(csv_data).to_csv(csv_path, index=False)
#     print(f"💾 CSV summary:      {csv_path}\n")
    
#     return detailed_path, log_path, csv_path


# # ============================================================================
# # MAIN
# # ============================================================================

# def main(audit_file: str):
#     """Main execution pipeline"""
    
#     print("Starting ZeroWatch CVE Matching Pipeline...\n")
    
#     api_keys = Config.load_api_keys()
#     db_products = load_cve_database()
    
#     if not db_products:
#         print("❌ Cannot proceed without database")
#         return
    
#     print(f"📂 Loading audit data: {audit_file}")
    
#     with open(audit_file) as f:
#         audit_data = json.load(f)
    
#     print(f"✅ Loaded {len(audit_data)} software items\n")
    
#     matcher = HybridMatcher(db_products, api_keys)
    
#     print("="*80)
#     print("STARTING HYBRID MATCHING PIPELINE")
#     print("="*80 + "\n")
    
#     start_time = time.time()
#     results = matcher.batch_match(audit_data)
#     duration = time.time() - start_time
    
#     matcher.print_stats()
    
#     print(f"\n⏱️  Total pipeline time: {duration:.2f}s")
    
#     print("\n" + "="*80)
#     print("SAVING RESULTS")
#     print("="*80 + "\n")
    
#     save_results(results, matcher, audit_file)
    
#     print("\n" + "="*80)
#     print("PIPELINE COMPLETE!")
#     print("="*80)


# if __name__ == "__main__":
#     import sys
    
#     if len(sys.argv) < 2:
#         print("Usage: python 02_hybrid_matcher.py <audit_file.json>")
#         print("\nExample:")
#         print("  python scripts/02_hybrid_matcher.py input/audit_jsons/aryan_audit.json")
#         sys.exit(1)
    
#     audit_file = sys.argv[1]
    
#     if not os.path.exists(audit_file):
#         print(f"❌ File not found: {audit_file}")
#         sys.exit(1)
    
#     main(audit_file)
# FILE: scripts/02_hybrid_matcher.py

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

    # Paths
    PROJECT_ROOT = Path(__file__).parent.parent
    DATA_DIR = PROJECT_ROOT / 'data'
    OUTPUT_DIR = PROJECT_ROOT / 'output'
    LOGS_DIR = OUTPUT_DIR / 'transparent_logs'

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

def get_candidates_token_sort(
    query: str,
    search_texts: List[str],
    db_products: List[Dict],
    top_k: int
) -> List[Dict]:
    """Get top K candidates using Token Sort Ratio."""

    matches = process.extract(
        query,
        search_texts,
        scorer=fuzz.token_sort_ratio,
        limit=top_k
    )

    candidates: List[Dict] = []
    for matched_text, score, idx in matches:
        product = db_products[idx]
        candidates.append({
            'vendor': product['vendor'],
            'product': product['product'],
            'canonical': product['canonical'],
            'score': score / 100.0,
            'method': 'token_sort',
            'matched_text': matched_text,
        })

    return candidates


def get_candidates_partial_ratio(
    query: str,
    search_texts: List[str],
    db_products: List[Dict],
    top_k: int
) -> List[Dict]:
    """Get top K candidates using Partial Ratio."""

    matches = process.extract(
        query,
        search_texts,
        scorer=fuzz.partial_ratio,
        limit=top_k
    )

    candidates: List[Dict] = []
    for matched_text, score, idx in matches:
        product = db_products[idx]
        candidates.append({
            'vendor': product['vendor'],
            'product': product['product'],
            'canonical': product['canonical'],
            'score': score / 100.0,
            'method': 'partial_ratio',
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
    """Transparent Gemini verification with round-robin API key usage"""

    def __init__(self, api_keys: Dict[str, str]):
        self.api_keys = api_keys
        self.member_names: List[str] = list(api_keys.keys())
        self.current_idx: int = 0
        self.usage_stats: Dict[str, int] = {name: 0 for name in self.member_names}

        if self.member_names:
            print(f"✅ Initialized Gemini with {len(self.member_names)} API keys\n")
        else:
            print("⚠️  GeminiVerifier initialized with 0 API keys\n")

    def _get_next_member(self) -> Tuple[Optional[str], Optional[str]]:
        """Round-robin through team members' API keys."""
        if not self.member_names:
            return None, None

        member_name = self.member_names[self.current_idx]
        api_key = self.api_keys[member_name]

        self.usage_stats[member_name] += 1
        self.current_idx = (self.current_idx + 1) % len(self.member_names)

        return member_name, api_key

    def _strip_code_fences(self, text: str) -> str:
        """Strip ```json ... ``` or ``` ... ``` fences from LLM output safely."""
        if '```' not in text:
            return text.strip()

        # Typical pattern: ```json\n{...}\n```
        parts = text.split('```')
        # parts: ['', 'json\n{...}\n', ''] or similar
        for segment in parts:
            segment = segment.strip()
            if segment.startswith('{') and segment.endswith('}'):
                return segment
            if '{' in segment and '}' in segment:
                inside = segment[segment.find('{'): segment.rfind('}') + 1]
                if inside.strip().startswith('{'):
                    return inside.strip()

        return text.strip()

    def verify_match(self, original_name: str, candidates: List[Dict]) -> Dict:
        """Ask Gemini to select best match from candidates."""

        # Build candidates list text
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

        try:
            member_name, api_key = self._get_next_member()
            if not api_key:
                raise RuntimeError("No Gemini API keys available")

            # Configure API key for this specific request
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-2.0-flash-exp')

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

            # Try to parse JSON
            parsed = json.loads(text)

            # Add transparency metadata
            parsed['gemini_api_key_owner'] = member_name
            parsed['gemini_response_time_ms'] = round(gemini_time * 1000, 2)
            parsed['gemini_raw_response'] = text[:500]
            parsed['total_candidates_provided'] = len(candidates)

            if parsed.get('matched'):
                canonical = parsed.get('selected_canonical', '')
                if '/' in canonical:
                    vendor, product = canonical.split('/', 1)
                    parsed['vendor'] = vendor
                    parsed['product'] = product

            return parsed

        except Exception as e:
            print(f"⚠️  Gemini verification failed: {str(e)[:150]}")

            # Fallback: use highest string match
            best = candidates[0]

            return {
                'matched': True,
                'selected_canonical': best['canonical'],
                'vendor': best['vendor'],
                'product': best['product'],
                'confidence': best['score'],
                'reasoning': 'Gemini unavailable or parsing failed, using highest string match',
                'gemini_api_key_owner': 'fallback',
                'gemini_response_time_ms': 0,
                'total_candidates_provided': len(candidates),
                'fallback_used': True,
            }

    def print_usage_stats(self):
        """Print API key usage statistics"""

        print("\n" + "=" * 80)
        print("GEMINI API KEY USAGE STATISTICS")
        print("=" * 80 + "\n")

        for member, count in self.usage_stats.items():
            print(f"  {member:20s}: {count:4d} requests")

        total = sum(self.usage_stats.values())
        print(f"\n  Total: {total} requests")


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
