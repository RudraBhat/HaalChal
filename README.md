
# 📦 HaalChal – Local IPC Chat
HaalChal is a secure-by-design, single-machine chat sandbox that demonstrates how core operating-system ideas come together in plain C. Each user signs in with a mobile number, belongs to a unique FIFO channel, and exchanges both text and files with other locally running user sessions. Logs, contact mappings, and shared files persist between runs so you can pick up any conversation later. Every conversation is now protected by a Hill-cipher-style 3×3 matrix derived from the two mobile numbers, so ciphertext is stored on disk while each terminal sees the decrypted text in real time.

---

## ✨ Concepts & Why They Matter
- **Process management:** file transfers fork child processes and collect their status with `waitpid()`. This keeps the UI responsive and shows how work can be offloaded safely.
- **Inter-process communication:** named pipes (`channels/<mobile>.fifo`) let unrelated user processes chat; anonymous pipes carry status text from helper children back to parents. This mirrors the “talking processes” objective of the project proposal while keeping the Hill cipher fully local.
- **Synchronization & multithreading:** every session spawns a listener thread with `pthread_create()` so incoming messages never block the main REPL. Mutexes guard chat logs and the contacts database, ensuring only one writer touches shared state at a time—exactly the “ensuring safe append operations and ordered access inside each session” requirement, even while ciphertext is appended.
- **Signal handling:** lightweight handlers for `SIGINT`/`SIGTERM` set a global flag so both threads exit gracefully, FIFOs get unlinked, and files are flushed. This reflects how OS signals can coordinate shutdown without corrupting data.
- **File I/O & persistence:** conversations become timestamped ciphertext logs (`chatlogs/<a>_<b>.txt`), contacts live in `contacts.db`, and transferred files stay under `storage/<username>/`. This covers directory management, `fopen`/`fgets`/`fputs`, and the “personal cloud” persistence goals.
- **Encryption & decryption:** per-pair Hill matrices encrypt every message (including file notifications) before they hit disk or the FIFO, and listener/history paths decrypt on the fly so the terminal always shows the original text while storage stays encrypted.

---

## 🗂 Layout

```plaintext
HaalChal/
├── haalchal_ipc.c  – single binary
├── contacts.db     – mobile ↔ name CSV
├── chatlogs/       – auto-created pair logs
├── storage/        – per-user files
├── channels/       – runtime FIFOs
├── Makefile
```

---

## ⚙️ Build & Run

```bash
make                # builds ./haalchal_ipc
./haalchal_ipc
```

The program auto-creates `contacts.db` entries. If a mobile number is not found, HaalChal will ask you to enter a username for it. Start one terminal per user from the project root, enter the mobile number when prompted, and you will see `channels/<mobile>.fifo` appear for each running session.

---

## 💬 Commands
- `msg <mobile> <text>` – auto-creates the contact if missing, shows the prior log once, appends a timestamped line, and sends the payload over the FIFO.
- `sendfile <mobile> <path>` – child process copies the file into the recipient’s storage folder and logs the event, then a small message notifies them.
- `history <mobile>` – decrypts and prints the full transcript for that pair from `chatlogs/<pair>.txt`.
- `list` – lists files under your `storage/<username>/`.
- `exit` – closes the FIFO, cancels the listener, and removes the named pipe.

The listener thread prints incoming messages inline and writes them to the correct log, so every new session resumes where the previous chat ended.

---

## 🧭 Ideas to Try Next
- Extend the Hill cipher to encrypt the raw files themselves before writing into `storage/<username>/`.
- Swap FIFOs for Unix/TCP sockets to extend HaalChal across a LAN while preserving the same command set.
- Add CLI helpers for managing contacts/logs or for exporting encrypted archives.
