import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import chromadb
import os
import gc
import glob

class AirGappedScanner:
    def __init__(self):
        print("🛡️ Loading Air-Gapped Security Engine...")
        
        # ⚡ LAG FIX: Limit CPU threads so Windows stays responsive
        torch.set_num_threads(4) 
        
        self.model_path = os.path.abspath("./Models") 
        self.db_path = os.path.abspath("./DB")
        
        # 1. Load Tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_path, 
            trust_remote_code=True
        )
        
        # 2. Load Model Weights
        print("🧠 Loading Model Weights (Direct CPU)...")
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_path,
            torch_dtype=torch.float32,
            low_cpu_mem_usage=True,
            trust_remote_code=True,
            device_map="cpu"
        )
        
        gc.collect()
        
        # 3. Connect to Database
        print("📚 Connecting to Database...")
        self.db_client = chromadb.PersistentClient(path=self.db_path)
        existing = self.db_client.list_collections()
        col_name = existing[0].name if existing else "owasp_mitigations"
        print(f"✅ Linked to collection: {col_name}")
        self.collection = self.db_client.get_collection(name=col_name)

    def run_audit(self, test_code, file_name):
        print(f"\n" + "="*60)
        print(f"🔍 AUDITING: {file_name}")
        print("="*60)
        
        prompt = (
            f"Instruction: You are a Security Expert. Classify this code as SAFE or EXPLOIT.\n"
            f"Criteria for EXPLOIT: pickle.loads, string concatenation in SQL, or unvalidated input.\n"
            f"Criteria for SAFE: json.loads, parameterized queries, or hardcoded strings.\n\n"
            f"Code: {test_code}\n"
            f"Verdict:"
        )
        
        inputs = self.tokenizer(prompt, return_tensors="pt")
        
        print("⏳ AI is calculating verdict...")
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs, 
                max_new_tokens=5, 
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id
            )
        
        response = self.tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True).strip().upper()

        # Database Retrieval
        search_query = "pickle loads vulnerability" if "pickle" in test_code else test_code
        results = self.collection.query(query_texts=[search_query], n_results=1)
        owasp_fix = results['documents'][0][0] if results['documents'] else "No mitigation found."

        print("\n" + "*"*60)
        
        is_exploit = "EXPLOIT" in response or "VULNERABLE" in response
        
        # Manual Override for obvious issues
        if "pickle.loads" in test_code or ("SELECT" in test_code.upper() and "+" in test_code):
            is_exploit = True

        if is_exploit:
            print("🚨 FINAL RESULT: NOT SAFE (VULNERABILITY DETECTED)")
            print("*"*60)
            print(f"\nOFFICIAL OWASP MITIGATION:\n{owasp_fix}")
        else:
            print("✅ FINAL RESULT: SAFE")
            print("*"*60)
            print("\nThis code follows secure standards.")

        print("="*60)

def run_batch_scan(scanner, folder_path):
    """Recursively finds all .py files in a folder and audits them."""
    print(f"\n🚀 STARTING BATCH SCAN IN: {folder_path}")
    
    # Matches all .py files in the folder and all subfolders
    files = glob.glob(os.path.join(folder_path, "**/*.py"), recursive=True)
    
    if not files:
        print("❌ No Python files found in that directory.")
        return

    print(f"📂 Found {len(files)} files to analyze.\n")

    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Pass the relative path for cleaner printing
                scanner.run_audit(content, os.path.relpath(file_path))
        except Exception as e:
            print(f"⚠️ Error reading {file_path}: {e}")

# --- Main Execution ---
if __name__ == "__main__":
    try:
        # Initialize the engine once
        scanner = AirGappedScanner()
        
        # --- BATCH SCAN CONFIG ---
        # Specify the folder you want to scan here (e.g., './my_scripts')
        target_folder = r"D:\python" 
        
        if os.path.exists(target_folder):
            run_batch_scan(scanner, target_folder)
            print("\n✨ Batch scan complete.")
        else:
            print(f"\nℹ️ Folder '{target_folder}' not found. Please create it or update the path.")
        
    except Exception as e:
        print(f"❌ Initialization Error: {e}")