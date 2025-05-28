import tkinter as tk
from tkinter import filedialog, ttk
import json
import zipfile
import re

class ModpackAnalyzer:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("MRPack Analyzer")
        self.root.geometry("800x600")
        
        style = ttk.Style()
        style.configure("TButton", padding=10)
        style.configure("TLabel", padding=5)
        
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.file_frame = ttk.Frame(self.main_frame)
        self.file_frame.pack(fill=tk.X, pady=10)
        
        self.file_label = ttk.Label(self.file_frame, text="Select .mrpack file:")
        self.file_label.pack(side=tk.LEFT)
        
        self.file_button = ttk.Button(self.file_frame, text="Browse", command=self.select_file)
        self.file_button.pack(side=tk.RIGHT)
        
        self.result_frame = ttk.Frame(self.main_frame)
        self.result_frame.pack(fill=tk.BOTH, expand=True)
        
        self.result_text = tk.Text(self.result_frame, wrap=tk.WORD, height=20)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.result_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        # Export buttons frame
        self.export_frame = ttk.Frame(self.main_frame)
        self.export_frame.pack(pady=10)
        
        self.export_json_button = ttk.Button(self.export_frame, text="Export as JSON", command=lambda: self.export_analysis("json"))
        self.export_json_button.pack(side=tk.LEFT, padx=5)
        
        self.export_txt_button = ttk.Button(self.export_frame, text="Export as TXT", command=lambda: self.export_analysis("txt"))
        self.export_txt_button.pack(side=tk.LEFT, padx=5)
        
        self.analyzed_data = {}
    
    def format_for_ai(self, data, indent=0):
        output = []
        indent_str = "  " * indent
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    output.append(f"{indent_str}{key}:")
                    output.append(self.format_for_ai(value, indent + 1))
                else:
                    output.append(f"{indent_str}{key}: {value}")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    output.append(self.format_for_ai(item, indent))
                else:
                    output.append(f"{indent_str}- {item}")
        
        return "\n".join(output) if isinstance(output, list) else str(output)
    
    def generate_ai_readable_text(self):
        sections = [
            "=== MINECRAFT MODPACK ANALYSIS ===",
            "",
            "[METADATA]"]
        sections.extend(self.format_for_ai(self.analyzed_data["metadata"]).split("\n"))
        
        sections.extend(["", "[GAME INFORMATION]"])
        sections.extend(self.format_for_ai(self.analyzed_data["game_info"]).split("\n"))
        
        sections.extend(["", "[STATISTICS]"])
        sections.extend(self.format_for_ai(self.analyzed_data["statistics"]).split("\n"))
        
        sections.extend(["", "[COMPONENTS]"])
        for component_type in ["mods", "datapacks", "resourcepacks", "shaders"]:
            if self.analyzed_data["components"][component_type]:
                sections.append(f"\n{component_type.upper()}:")
                for item in self.analyzed_data["components"][component_type]:
                    sections.extend(self.format_for_ai(item, 1).split("\n"))
        
        return "\n".join(sections)
    
    def detect_game_edition(self, files):
        java_indicators = ['forge', 'fabric', 'quilt', 'neoforge']
        bedrock_indicators = ['behavior_pack', 'resource_pack', '.mcpack', '.mcaddon']
        
        edition = {
            "java": False,
            "bedrock": False,
            "loader": None,
            "confidence": "unknown"
        }
        
        for file in files:
            path = file.get('path', '').lower()
            
            for indicator in java_indicators:
                if indicator in path:
                    edition["java"] = True
                    edition["loader"] = indicator
                    break
            
            for indicator in bedrock_indicators:
                if indicator in path:
                    edition["bedrock"] = True
                    break
        
        if edition["java"] and not edition["bedrock"]:
            edition["confidence"] = "high"
        elif edition["bedrock"] and not edition["java"]:
            edition["confidence"] = "high"
        elif edition["java"] and edition["bedrock"]:
            edition["confidence"] = "mixed"
        
        return edition
    
    def parse_game_version(self, version_str):
        if not version_str:
            return None
        
        version_info = {
            "full": version_str,
            "major": None,
            "minor": None,
            "patch": None,
            "snapshot": False,
            "release_type": "release"
        }
        
        if 'w' in version_str.lower() or 'pre' in version_str.lower():
            version_info["snapshot"] = True
            version_info["release_type"] = "snapshot"
        elif 'rc' in version_str.lower():
            version_info["release_type"] = "release_candidate"
        elif 'beta' in version_str.lower():
            version_info["release_type"] = "beta"
        elif 'alpha' in version_str.lower():
            version_info["release_type"] = "alpha"
        
        version_match = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', version_str)
        if version_match:
            version_info["major"] = int(version_match.group(1))
            version_info["minor"] = int(version_match.group(2))
            version_info["patch"] = int(version_match.group(3)) if version_match.group(3) else None
        
        return version_info
    
    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("MRPack files", "*.mrpack")])
        if file_path:
            self.analyze_mrpack(file_path)
    
    def analyze_mrpack(self, file_path):
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                if 'modrinth.index.json' in zip_ref.namelist():
                    with zip_ref.open('modrinth.index.json') as index_file:
                        data = json.load(index_file)
                        self.parse_mrpack_data(data)
                else:
                    self.result_text.insert(tk.END, "Error: modrinth.index.json not found in the mrpack file.\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error analyzing file: {str(e)}\n")
    
    def parse_mrpack_data(self, data):
        game_version = data.get("game_version", [])
        if isinstance(game_version, str):
            game_version = [game_version]
        
        self.analyzed_data = {
            "metadata": {
                "name": data.get("name", ""),
                "version": data.get("version", ""),
                "author": data.get("author", ""),
                "description": data.get("description", "")
            },
            "game_info": {
                "versions": [
                    self.parse_game_version(ver) for ver in game_version
                ],
                "edition": self.detect_game_edition(data.get("files", [])),
                "dependencies": data.get("dependencies", {})
            },
            "components": {
                "mods": [],
                "datapacks": [],
                "resourcepacks": [],
                "shaders": []
            },
            "statistics": {
                "total_size": 0,
                "file_count": 0,
                "mod_count": 0,
                "datapack_count": 0,
                "resourcepack_count": 0,
                "shader_count": 0
            },
            "file_structure": {}
        }
        
        if 'files' in data:
            for file in data['files']:
                file_info = {
                    "path": file.get("path", ""),
                    "hash": file.get("hashes", {}),
                    "size": file.get("fileSize", 0),
                    "env": file.get("env", {}),
                    "downloads": file.get("downloads", []),
                    "metadata": {
                        "project_id": file.get("project_id", ""),
                        "version_id": file.get("version_id", ""),
                        "required": file.get("required", True)
                    }
                }
                
                self.analyzed_data["statistics"]["total_size"] += file_info["size"]
                self.analyzed_data["statistics"]["file_count"] += 1
                
                path = file.get("path", "").lower()
                if path.endswith(".jar"):
                    self.analyzed_data["components"]["mods"].append(file_info)
                    self.analyzed_data["statistics"]["mod_count"] += 1
                elif path.endswith(".zip") or 'datapack' in path:
                    self.analyzed_data["components"]["datapacks"].append(file_info)
                    self.analyzed_data["statistics"]["datapack_count"] += 1
                elif 'resourcepack' in path or path.endswith(".zip"):
                    self.analyzed_data["components"]["resourcepacks"].append(file_info)
                    self.analyzed_data["statistics"]["resourcepack_count"] += 1
                elif 'shader' in path:
                    self.analyzed_data["components"]["shaders"].append(file_info)
                    self.analyzed_data["statistics"]["shader_count"] += 1
                
                parts = path.split('/')
                current = self.analyzed_data["file_structure"]
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                current[parts[-1]] = file_info
        
        self.display_analysis()
    
    def display_analysis(self):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, self.generate_ai_readable_text())
    
    def export_analysis(self, format_type="json"):
        if not self.analyzed_data:
            self.result_text.insert(tk.END, "\nNo data to export. Please analyze a modpack first.\n")
            return
        
        filetypes = [("JSON files", "*.json")] if format_type == "json" else [("Text files", "*.txt")]
        default_ext = ".json" if format_type == "json" else ".txt"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=filetypes,
            title=f"Export Analysis as {format_type.upper()}"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    if format_type == "json":
                        json.dump(self.analyzed_data, f, indent=2)
                    else:
                        f.write(self.generate_ai_readable_text())
                self.result_text.insert(tk.END, f"\nAnalysis exported to {file_path}\n")
            except Exception as e:
                self.result_text.insert(tk.END, f"\nError exporting analysis: {str(e)}\n")
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = ModpackAnalyzer()
    app.run()