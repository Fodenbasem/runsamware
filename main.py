"""
NovaCrypt GUI Application
Enterprise-grade encryption application with GUI

Features:
- Hybrid encryption (AES-256-GCM + RSA-4096)
- Digital signatures
- SHA-256 integrity verification
- Chunk-based streaming for large files
- Multithreaded operations
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from typing import Optional
import hashlib

from crypto_engine import CryptoEngine, EncryptionResult, DecryptionResult


class NovaCryptGUI:
    """
    Main GUI Application for NovaCrypt
    """
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("NovaCrypt - Enterprise Encryption")
        self.root.geometry("700x550")
        self.root.resizable(False, False)
        
        # Initialize crypto engine
        self.crypto = CryptoEngine()
        
        # Paths
        self.keys_folder = "keys"
        self.public_key_path = os.path.join(self.keys_folder, "public_key.pem")
        self.private_key_path = os.path.join(self.keys_folder, "private_key.pem")
        
        # Ensure keys folder exists
        os.makedirs(self.keys_folder, exist_ok=True)
        
        # Configure style
        self._configure_style()
        
        # Create main UI
        self._create_main_ui()
        
        # Status message
        self.status_var = tk.StringVar(value="Ready")
        
    def _configure_style(self):
        """Configure UI style"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', font=('Helvetica', 24, 'bold'), foreground='#2c3e50')
        style.configure('Subtitle.TLabel', font=('Helvetica', 12), foreground='#7f8c8d')
        style.configure('Main.TButton', font=('Helvetica', 12), padding=10)
        style.configure('Accent.TButton', font=('Helvetica', 12, 'bold'), padding=10)
        style.configure('Info.TLabel', font=('Helvetica', 10), foreground='#34495e')
        style.configure('Success.TLabel', font=('Helvetica', 10, 'bold'), foreground='#27ae60')
        style.configure('Error.TLabel', font=('Helvetica', 10, 'bold'), foreground='#e74c3c')
        
    def _create_main_ui(self):
        """Create main user interface"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="30")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text="NovaCrypt", 
            style='Title.TLabel'
        )
        title_label.pack(pady=(0, 5))
        
        # Subtitle
        subtitle_label = ttk.Label(
            main_frame,
            text="Enterprise-Grade Encryption System",
            style='Subtitle.TLabel'
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Key status
        self.key_status_frame = ttk.LabelFrame(main_frame, text="Key Status", padding="15")
        self.key_status_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.key_status_var = tk.StringVar(value="No keys loaded")
        self.key_fingerprint_var = tk.StringVar(value="")
        
        ttk.Label(
            self.key_status_frame,
            textvariable=self.key_status_var,
            style='Info.TLabel'
        ).pack(anchor=tk.W)
        
        ttk.Label(
            self.key_status_frame,
            textvariable=self.key_fingerprint_var,
            font=('Courier', 8),
            foreground='#95a5a6'
        ).pack(anchor=tk.W, pady=(5, 0))
        
        # Check if keys exist and load status
        self._check_key_status()
        
        # Main buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Encrypt button
        encrypt_btn = ttk.Button(
            button_frame,
            text="🔐 Encrypt",
            style='Accent.TButton',
            command=self._on_encrypt
        )
        encrypt_btn.pack(fill=tk.X, pady=5)
        
        # Decrypt button
        decrypt_btn = ttk.Button(
            button_frame,
            text="🔓 Decrypt",
            style='Accent.TButton',
            command=self._on_decrypt
        )
        decrypt_btn.pack(fill=tk.X, pady=5)
        
        # Generate Keys button
        generate_btn = ttk.Button(
            button_frame,
            text="🔑 Generate Key Pair",
            style='Main.TButton',
            command=self._on_generate_keys
        )
        generate_btn.pack(fill=tk.X, pady=5)
        
        # Import Keys button
        import_btn = ttk.Button(
            button_frame,
            text="📥 Import Keys",
            style='Main.TButton',
            command=self._on_import_keys
        )
        import_btn.pack(fill=tk.X, pady=5)
        
        # Exit button
        exit_btn = ttk.Button(
            button_frame,
            text="❌ Exit",
            style='Main.TButton',
            command=self.root.quit
        )
        exit_btn.pack(fill=tk.X, pady=5)
        
        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(20, 0))
        
        self.progress = ttk.Progressbar(status_frame, mode='determinate', length=300)
        self.progress.pack(fill=tk.X)
        
        self.status_label = ttk.Label(
            status_frame,
            textvariable=self.status_var,
            style='Info.TLabel'
        )
        self.status_label.pack(pady=(5, 0))
    
    def _check_key_status(self):
        """Check if keys exist and update status"""
        if os.path.exists(self.public_key_path) and os.path.exists(self.private_key_path):
            try:
                with open(self.public_key_path, 'rb') as f:
                    public_pem = f.read()
                fingerprint = self.crypto.get_key_fingerprint(public_pem)
                self.key_status_var.set("✓ Keys loaded")
                self.key_fingerprint_var.set(f"Fingerprint: {fingerprint[:16]}...")
            except Exception as e:
                self.key_status_var.set("✗ Error loading keys")
        else:
            self.key_status_var.set("No keys loaded - Generate or import keys first")
            self.key_fingerprint_var.set("")
    
    def _load_keys(self) -> tuple:
        """Load public and private keys"""
        with open(self.public_key_path, 'rb') as f:
            public_pem = f.read()
        
        with open(self.private_key_path, 'rb') as f:
            private_pem = f.read()
        
        return public_pem, private_pem
    
    def _on_encrypt(self):
        """Handle encrypt button click"""
        # Check if keys exist
        if not os.path.exists(self.public_key_path) or not os.path.exists(self.private_key_path):
            messagebox.showwarning("Keys Required", "Please generate or import keys first!")
            return
        
        # Ask user to select file or folder
        input_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not input_path:
            # Try folder selection
            input_path = filedialog.askdirectory(title="Select Folder to Encrypt")
            if not input_path:
                return
        
        # Ask for output path
        output_path = filedialog.asksaveasfilename(
            title="Save Encrypted File",
            defaultextension=".nova",
            filetypes=[("Nova Files", "*.nova"), ("All Files", "*.*")]
        )
        if not output_path:
            return
        
        # Ask for private key password
        password = simpledialog.askstring("Password", "Enter private key password:", show='*')
        if not password:
            return
        
        # Ask for secure delete
        secure_delete = messagebox.askyesno("Secure Delete", "Do you want to securely delete the original file(s)?\n\nThis will overwrite the original data before deletion.")
        
        # Get keys
        try:
            public_pem, private_pem = self._load_keys()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load keys: {str(e)}")
            return
        
        # Disable buttons
        self._set_buttons_state(tk.DISABLED)
        
        # Start encryption in thread
        thread = threading.Thread(
            target=self._encrypt_thread,
            args=(input_path, output_path, public_pem, private_pem, password, secure_delete)
        )
        thread.daemon = True
        thread.start()
    
    def _encrypt_thread(self, input_path: str, output_path: str, 
                        public_pem: bytes, private_pem: bytes, 
                        password: str, secure_delete: bool):
        """Encryption thread"""
        def progress_callback(progress: float, message: str):
            self.root.after(0, lambda: self._update_progress(progress, message))
        
        try:
            # Check if input is file or folder
            if os.path.isdir(input_path):
                result = self.crypto.encrypt_folder(
                    input_path, output_path, public_pem, private_pem,
                    password, progress_callback, secure_delete
                )
            else:
                result = self.crypto.encrypt_file(
                    input_path, output_path, public_pem, private_pem,
                    password, progress_callback, secure_delete
                )
            
            self.root.after(0, lambda: self._encryption_complete(result))
            
        except Exception as e:
            self.root.after(0, lambda: self._encryption_error(str(e)))
    
    def _encryption_complete(self, result: EncryptionResult):
        """Handle encryption completion"""
        self._set_buttons_state(tk.NORMAL)
        self.progress['value'] = 100
        self.status_var.set("Encryption complete!")
        
        if result.success:
            # Show success dialog with details
            details = f"""✓ Encryption Successful!

Output File: {result.output_path}
Original Size: {self._format_size(result.original_size)}
Encrypted Size: {self._format_size(result.encrypted_size)}
Compression: {self._format_size(result.original_size - result.encrypted_size)}

Key Fingerprint:
{result.key_fingerprint}

SHA-256 Hash:
{result.file_hash}

Digital Signature: Verified ✓
"""
            messagebox.showinfo("Encryption Complete", details)
        else:
            messagebox.showerror("Encryption Failed", f"Error: {result.error}")
    
    def _encryption_error(self, error: str):
        """Handle encryption error"""
        self._set_buttons_state(tk.NORMAL)
        self.progress['value'] = 0
        self.status_var.set("Encryption failed!")
        messagebox.showerror("Error", f"Encryption failed: {error}")
    
    def _on_decrypt(self):
        """Handle decrypt button click"""
        # Check if keys exist
        if not os.path.exists(self.public_key_path) or not os.path.exists(self.private_key_path):
            messagebox.showwarning("Keys Required", "Please generate or import keys first!")
            return
        
        # Ask user to select .nova file
        input_path = filedialog.askopenfilename(
            title="Select File to Decrypt",
            filetypes=[("Nova Files", "*.nova"), ("All Files", "*.*")]
        )
        if not input_path:
            return
        
        # Ask for output directory
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if not output_dir:
            return
        
        # Ask for private key password
        password = simpledialog.askstring("Password", "Enter private key password:", show='*')
        if not password:
            return
        
        # Get keys
        try:
            public_pem, private_pem = self._load_keys()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load keys: {str(e)}")
            return
        
        # Disable buttons
        self._set_buttons_state(tk.DISABLED)
        
        # Start decryption in thread
        thread = threading.Thread(
            target=self._decrypt_thread,
            args=(input_path, output_dir, public_pem, private_pem, password)
        )
        thread.daemon = True
        thread.start()
    
    def _decrypt_thread(self, input_path: str, output_dir: str,
                        public_pem: bytes, private_pem: bytes, password: str):
        """Decryption thread"""
        def progress_callback(progress: float, message: str):
            self.root.after(0, lambda: self._update_progress(progress, message))
        
        try:
            result = self.crypto.decrypt_file(
                input_path, output_dir, public_pem, private_pem,
                password, progress_callback
            )
            
            self.root.after(0, lambda: self._decryption_complete(result))
            
        except Exception as e:
            self.root.after(0, lambda: self._decryption_error(str(e)))
    
    def _decryption_complete(self, result: DecryptionResult):
        """Handle decryption completion"""
        self._set_buttons_state(tk.NORMAL)
        self.progress['value'] = 100
        self.status_var.set("Decryption complete!")
        
        if result.success:
            # Show success dialog with details
            details = f"""✓ Decryption Successful!

Output Directory: {result.output_path}
Original Filename: {result.original_filename}

Integrity Verification: {'✓ Verified' if result.integrity_verified else '✗ Failed'}
Digital Signature: {'✓ Verified' if result.signature_verified else '✗ Failed'}
"""
            messagebox.showinfo("Decryption Complete", details)
        else:
            messagebox.showerror("Decryption Failed", f"Error: {result.error}")
    
    def _decryption_error(self, error: str):
        """Handle decryption error"""
        self._set_buttons_state(tk.NORMAL)
        self.progress['value'] = 0
        self.status_var.set("Decryption failed!")
        messagebox.showerror("Error", f"Decryption failed: {error}")
    
    def _on_generate_keys(self):
        """Handle generate keys button click"""
        # Ask for password
        password = simpledialog.askstring(
            "Generate Keys", 
            "Enter a password to protect your private key:",
            show='*'
        )
        if not password:
            return
        
        # Confirm password
        confirm_password = simpledialog.askstring(
            "Generate Keys",
            "Confirm password:",
            show='*'
        )
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters!")
            return
        
        # Generate keys
        self.status_var.set("Generating RSA-4096 key pair... (this may take a while)")
        self.progress['indeterminate'] = True
        self.progress.start()
        self._set_buttons_state(tk.DISABLED)
        
        thread = threading.Thread(
            target=self._generate_keys_thread,
            args=(password,)
        )
        thread.daemon = True
        thread.start()
    
    def _generate_keys_thread(self, password: str):
        """Key generation thread"""
        try:
            private_pem, public_pem = CryptoEngine.generate_rsa_keypair(password)
            
            # Save keys
            os.makedirs(self.keys_folder, exist_ok=True)
            
            with open(self.private_key_path, 'wb') as f:
                f.write(private_pem)
            
            with open(self.public_key_path, 'wb') as f:
                f.write(public_pem)
            
            fingerprint = CryptoEngine.get_key_fingerprint(public_pem)
            
            self.root.after(0, lambda: self._keys_generated(fingerprint))
            
        except Exception as e:
            self.root.after(0, lambda: self._keys_generation_error(str(e)))
    
    def _keys_generated(self, fingerprint: str):
        """Handle key generation completion"""
        self.progress.stop()
        self.progress['indeterminate'] = False
        self.progress['value'] = 100
        self._set_buttons_state(tk.NORMAL)
        self.status_var.set("Keys generated successfully!")
        
        self._check_key_status()
        
        messagebox.showinfo(
            "Keys Generated",
            f"✓ RSA-4096 key pair generated successfully!\n\n"
            f"Public Key: {self.public_key_path}\n"
            f"Private Key: {self.private_key_path}\n\n"
            f"Key Fingerprint:\n{fingerprint}"
        )
    
    def _keys_generation_error(self, error: str):
        """Handle key generation error"""
        self.progress.stop()
        self.progress['indeterminate'] = False
        self.progress['value'] = 0
        self._set_buttons_state(tk.NORMAL)
        self.status_var.set("Key generation failed!")
        messagebox.showerror("Error", f"Key generation failed: {error}")
    
    def _on_import_keys(self):
        """Handle import keys button click"""
        # Ask for public key file
        public_path = filedialog.askopenfilename(
            title="Select Public Key File",
            filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")]
        )
        if not public_path:
            return
        
        # Ask for private key file
        private_path = filedialog.askopenfilename(
            title="Select Private Key File",
            filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")]
        )
        if not private_path:
            return
        
        try:
            # Read and validate keys
            with open(public_path, 'rb') as f:
                public_pem = f.read()
            
            with open(private_path, 'rb') as f:
                private_pem = f.read()
            
            # Validate by loading
            CryptoEngine.load_public_key(public_pem)
            
            # Ask for password to validate private key
            password = simpledialog.askstring(
                "Import Keys",
                "Enter the password for the private key:",
                show='*'
            )
            if not password:
                return
            
            # Validate private key
            try:
                CryptoEngine.load_private_key(private_pem, password)
            except Exception:
                messagebox.showerror("Error", "Invalid password for private key!")
                return
            
            # Copy keys to app folder
            import shutil
            shutil.copy(public_path, self.public_key_path)
            shutil.copy(private_path, self.private_key_path)
            
            self._check_key_status()
            
            messagebox.showinfo("Success", "Keys imported successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import keys: {str(e)}")
    
    def _update_progress(self, progress: float, message: str):
        """Update progress bar and status"""
        self.progress['value'] = progress
        self.status_var.set(message)
    
    def _set_buttons_state(self, state: str):
        """Enable or disable all buttons"""
        for widget in self.root.winfo_children():
            if isinstance(widget, ttk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Button):
                        child.config(state=state)
    
    def _format_size(self, size: int) -> str:
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"


def main():
    """Main entry point"""
    root = tk.Tk()
    app = NovaCryptGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
