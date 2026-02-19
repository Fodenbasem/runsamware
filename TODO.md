# NovaCrypt - Enterprise Encryption Application

## TODO List

### Phase 1: Core Crypto Module
- [ ] Create crypto_engine.py with:
  - [ ] AES-256-GCM encryption/decryption
  - [ ] RSA-4096 key generation
  - [ ] Hybrid encryption (encrypt AES key with RSA)
  - [ ] Digital signatures
  - [ ] SHA-256 integrity hashing
  - [ ] Chunk-based streaming for large files
  - [ ] ZIP compression

### Phase 2: GUI Application
- [ ] Create main.py with Tkinter GUI
- [ ] Main menu with Encrypt/Decrypt/Generate Keys/Exit buttons
- [ ] Key generation dialog
- [ ] File/Folder selection dialogs
- [ ] Progress bar implementation
- [ ] Threading for background operations

### Phase 3: Encryption Flow
- [ ] File/Folder auto-detection
- [ ] ZIP compression with max compression
- [ ] AES-256-GCM encryption
- [ ] RSA key encryption for AES key
- [ ] Digital signature
- [ ] .nova file format creation
- [ ] Secure delete option
- [ ] Display: key fingerprint, SHA-256, signature status

### Phase 4: Decryption Flow
- [ ] .nova file parsing
- [ ] Private key + password input
- [ ] Signature verification
- [ ] AES key decryption
- [ ] Data decryption
- [ ] Integrity verification
- [ ] Restore original structure

### Phase 5: Advanced Features
- [ ] Secure delete (multi-pass overwrite)
- [ ] Integrity verification panel
- [ ] Hash comparison
- [ ] Logging panel
- [ ] Exception handling

### Phase 6: Requirements & Testing
- [ ] Update requirements.txt with dependencies
- [ ] Test with large files
- [ ] Verify CPU/RAM usage
