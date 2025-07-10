# === IMPORTS AND STARTUP ===
# Stuff we need — might look like overkill but trust me, it’s all used eventually.

import os
import time
import json
import shutil
import re
import hashlib
import logging
import threading
from datetime import datetime, timedelta

# GUI building blocks
from tkinter import *
from tkinter import ttk, messagebox, simpledialog

# File system watching stuff
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# For trashing files (instead of permanent deletion)
import send2trash

# Threads, queues, and background tools
from concurrent.futures import ThreadPoolExecutor, wait
from queue import Queue
from tkinter.ttk import Progressbar
# === GLOBAL CONFIG SETUP ===

# Default folders we're always watching unless user overrides
DEFAULT_DIRECTORIES = [
    "Downloads", "Documents", "Pictures", "Music",
    "Videos", "Desktop", "Duplicates", "Untagged"
]

# Load saved directories if config exists, otherwise use hardcoded defaults
if os.path.exists("directories.json"):
    with open("directories.json", "r") as file:
        specific_directories = json.load(file)
else:
    specific_directories = [
        os.path.abspath(os.path.expanduser(f"~/{folder}"))
        for folder in DEFAULT_DIRECTORIES
    ]

# Set up logging — debug level by default, can be noisy
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("application.log", mode="a")
    ]
)

# Initial values for timers
next_emptying_time_2 = datetime.now() + timedelta(minutes=2)
next_scan_time = datetime.now() + timedelta(minutes=1)

TIMER_FILE = "timer_state.json"
SCAN_TIMER_FILE = "scan_timer_state.json"
# File types we don't want to touch (either too risky or irrelevant)
EXCLUDED_FILE_EXTENSIONS = [
    ".jar", ".py", ".pyc", ".class", ".o", ".java", ".so", ".dll", ".dylib",
    ".zip", ".tar", ".gz", ".7z", ".whl",
    ".ini", ".cfg", ".json", ".yaml", ".yml", ".iso",
    ".log", ".lock",
    ".exe", ".bat", ".sh",
    ".ipynb", ".csproj", ".sln", ".iml"
]

# Partial or temporary download files that we should ignore
TEMP_FILE_EXTENSIONS = [".part", ".tmp", ".crdownload"]

# Figure out how many workers to spawn for file operations
cpu_threads = os.cpu_count() or 4
max_workers = min(32, cpu_threads * 2)
executor = ThreadPoolExecutor(max_workers=max_workers)

# Setup a batch queue for background jobs
BATCH_SIZE = 100
process_queue = Queue()

# Simple hash cache — avoids re-hashing same file repeatedly
file_hash_cache = {}
MAX_CACHE_SIZE = 10000  # Don't let this balloon too much

# Lock used during file move operations
move_lock = threading.Lock()
MOVE_TIMEOUT = 30  # seconds
# === FILE TYPE HELPERS & CHECKSUM LOGIC ===

# Checks if the file extension marks this as temporary (incomplete download, etc.)
def is_temp_file(name):
    for ext in TEMP_FILE_EXTENSIONS:
        if name.lower().endswith(ext):
            return True
    return False

# Checks if file is the type we just don't want to touch
def is_excluded_file(name):
    for ext in EXCLUDED_FILE_EXTENSIONS:
        if name.lower().endswith(ext):
            return True
    return False

# Returns a SHA-256 hash for the file — we use this for detecting duplicates
def calculate_checksum(file_path, block_size=262144):  # 256KB blocks
    global file_hash_cache

    try:
        file_stat = os.stat(file_path)
        cache_key = (file_stat.st_size, file_stat.st_mtime)

        # Use the cached hash if we already calculated it for this file state
        if cache_key in file_hash_cache:
            return file_hash_cache[cache_key][0]

        # If cache is full, purge oldest ~30% of entries
        if len(file_hash_cache) > MAX_CACHE_SIZE:
            sorted_items = sorted(file_hash_cache.items(), key=lambda x: x[1][1])
            for key, _ in sorted_items[:int(0.3 * MAX_CACHE_SIZE)]:
                del file_hash_cache[key]

        # Actual hashing happens here
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(block_size), b''):
                hasher.update(chunk)

        result = hasher.hexdigest()
        file_hash_cache[cache_key] = (result, time.time())
        return result

    except Exception as err:
        logging.error(f"Checksum failed for {file_path}: {err}")
        return None
# Tells us whether a file is at least N minutes old
def is_file_older_than(file_path, minutes=1):
    try:
        file_age_sec = time.time() - os.path.getmtime(file_path)
        return file_age_sec > timedelta(minutes=minutes).total_seconds()
    except Exception as e:
        logging.error(f"Couldn't check file age for {file_path}: {e}")
        return False

# Handles scheduled deletion of a file after 60 seconds (acts like a soft-delete timer)
def schedule_duplicate_deletion(duplicate_path):
    logging.info(f"Scheduling deletion for {duplicate_path} after 60s")

    def delete_after_one_minute():
        time.sleep(60)
        if os.path.exists(duplicate_path):
            try:
                normalized_path = os.path.normpath(duplicate_path)
                send2trash.send2trash(normalized_path)
                logging.info(f"Sent duplicate '{os.path.basename(duplicate_path)}' to trash")
            except Exception as e:
                logging.error(f"Error trashing duplicate: {e}")

    threading.Thread(target=delete_after_one_minute, daemon=True).start()
# === TIMER STATE MANAGEMENT ===

# Save when we're supposed to next empty the Duplicates folder
def save_timer_state():
    try:
        with open(TIMER_FILE, "w") as f:
            json.dump({
                "next_emptying_time_2": next_emptying_time_2.isoformat()
            }, f)
    except Exception as e:
        logging.error(f"Couldn't save timer state: {e}")

# Save next scheduled duplicate scan
def save_scan_timer_state():
    try:
        with open(SCAN_TIMER_FILE, "w") as f:
            json.dump({
                "next_scan_time": next_scan_time.isoformat()
            }, f)
    except Exception as e:
        logging.error(f"Couldn't save scan timer state: {e}")

# Load last-known deletion timer and trigger deletion if we missed it
def load_timer_state():
    global next_emptying_time_2

    if os.path.exists(TIMER_FILE):
        try:
            with open(TIMER_FILE, "r") as f:
                data = json.load(f)
                saved_time = datetime.fromisoformat(data["next_emptying_time_2"])
                now = datetime.now()

                if now >= saved_time:
                    empty_duplicates_folder()
                    next_emptying_time_2 = now + timedelta(minutes=2)
                else:
                    next_emptying_time_2 = saved_time

        except Exception as e:
            logging.error(f"Failed to load deletion timer: {e}")

# Load scheduled scan state
def load_scan_timer_state():
    global next_scan_time

    if os.path.exists(SCAN_TIMER_FILE):
        try:
            with open(SCAN_TIMER_FILE, "r") as f:
                data = json.load(f)
                saved_time = datetime.fromisoformat(data["next_scan_time"])
                now = datetime.now()

                if now >= saved_time:
                    scan_for_duplicates()
                    next_scan_time = now + timedelta(minutes=1)
                else:
                    next_scan_time = saved_time

        except Exception as e:
            logging.error(f"Failed to load scan timer: {e}")
# Actually clears out ~/Duplicates (sends to trash, doesn’t delete permanently)
def empty_duplicates_folder():
    dup_path = os.path.normpath(os.path.expanduser("~/Duplicates"))

    if os.path.exists(dup_path):
        files_removed = False

        for fname in os.listdir(dup_path):
            full_path = os.path.join(dup_path, fname)
            try:
                send2trash.send2trash(full_path)
                logging.info(f"Moved duplicate '{fname}' to recycle bin")
                files_removed = True
            except Exception as e:
                logging.warning(f"Failed to send '{fname}' to trash: {e}")

        # If user is browsing Duplicates in the app, refresh the view
        if files_removed:
            try:
                if current_directory.get() == dup_path:
                    update_file_view(dup_path)
            except:
                pass  # UI might not be initialized yet
# Starts scanning all watched folders for duplicate files
def scan_for_duplicates():
    logging.info("🔍 Scanning all folders for duplicates...")

    try:
        for folder in specific_directories:
            if os.path.exists(folder) and os.path.basename(folder) != "Duplicates":
                scan_directory_duplicates(folder)
        logging.info("✅ Finished scanning for duplicates.")
        global next_scan_time
        next_scan_time = datetime.now() + timedelta(minutes=1)

    except Exception as e:
        logging.error(f"Error during duplicate scan: {e}")
# === DUPLICATE DETECTION ===

# Scans one specific folder for duplicate files using file hashes
def scan_directory_duplicates(directory):
    try:
        abs_dir = os.path.abspath(os.path.expanduser(directory))
        duplicates_dir = os.path.abspath(os.path.expanduser("~/Duplicates"))
        os.makedirs(duplicates_dir, exist_ok=True)
        local_hashes = {}

        valid_files = []
        for fname in os.listdir(abs_dir):
            full_path = os.path.join(abs_dir, fname)

            if os.path.isfile(full_path):
                if is_temp_file(fname) or is_excluded_file(fname):
                    continue
                valid_files.append((full_path, fname))

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [
                pool.submit(process_file_duplicate, path, name, local_hashes, duplicates_dir)
                for path, name in valid_files
            ]
            wait(futures)

    except Exception as e:
        logging.error(f"Couldn’t scan for duplicates in {directory}: {e}")
# Processes one file — hashes it, checks for duplicates, acts accordingly
def process_file_duplicate(file_path, filename, hash_map, duplicates_folder):
    try:
        checksum = calculate_checksum(file_path)
        if checksum:
            handle_duplicates(file_path, filename, checksum, hash_map, duplicates_folder)
    except Exception as e:
        logging.error(f"Problem processing file '{filename}': {e}")
# If we've seen this file's hash before, move it to the duplicates folder
def handle_duplicates(file_path, file_name, hash_val, seen_hashes, dup_folder):
    try:
        dup_folder = os.path.abspath(os.path.expanduser(dup_folder))

        if hash_val in seen_hashes:
            # Only move if it's older than 1 minute (still lets new files "settle")
            if is_file_older_than(file_path, minutes=1):
                logging.info(f"⚠️ Found duplicate: {file_path}")
                move_to_duplicates(file_path, file_name, dup_folder)
                return True
            else:
                logging.info(f"Skipping move — too new: {file_path}")
                return False
        else:
            seen_hashes[hash_val] = file_path
            return False

    except Exception as e:
        logging.error(f"Duplicate handling failed for {file_name}: {e}")
        return False
# Moves the duplicate into ~/Duplicates (renames if necessary)
def move_to_duplicates(file_path, filename, duplicates_dir):
    try:
        duplicates_dir = os.path.normpath(os.path.abspath(os.path.expanduser(duplicates_dir)))
        file_path = os.path.normpath(os.path.abspath(file_path))
        os.makedirs(duplicates_dir, exist_ok=True)

        base_name, ext = os.path.splitext(filename)
        target_name = filename
        count = 1

        # Rename if something with the same name already exists
        while os.path.exists(os.path.join(duplicates_dir, target_name)):
            target_name = f"{base_name} ({count}){ext}"
            count += 1

        new_path = os.path.join(duplicates_dir, target_name)
        shutil.move(file_path, new_path)
        logging.info(f"✅ Moved duplicate as: {target_name}")

        schedule_duplicate_deletion(new_path)

    except Exception as e:
        logging.error(f"Couldn't move duplicate '{filename}': {e}")
# === KEYWORD SORTING ===
# Try to match a file name to one of the keywords associated with any folder

def sort_files_by_keywords(file_path, file_name):
    try:
        logging.debug(f"Sorting file based on keywords: {file_name}")
        
        for folder_path, keywords in directory_keywords.items():
            for keyword in keywords:
                # Allow loose matches — treat underscores, spaces, dashes, etc. as separators
                pattern = rf"(^|[_\-\.\s]){re.escape(keyword)}([_\-\.\s]|$)"
                if re.search(pattern, file_name, re.IGNORECASE):
                    destination = os.path.abspath(os.path.expanduser(folder_path))

                    if not os.path.exists(destination):
                        logging.warning(f"Destination folder missing: {destination}")
                        continue

                    # Don't sort it if it's already in the right place
                    if os.path.dirname(file_path) == destination:
                        return True

                    move_file_to_category(file_path, destination)
                    return True

        return False

    except Exception as err:
        logging.error(f"Keyword sort failed for '{file_name}': {err}")
        return False
# Moves file into its keyword-matched folder.
# If batching is enabled, adds it to a queue instead of moving right away.

def move_file_to_category(file_path, destination_folder, batch=False):
    if batch:
        process_queue.put((file_path, destination_folder))
        if process_queue.qsize() >= BATCH_SIZE:
            process_batch()  # Ensure this function is defined below
        return True

    try:
        if not move_lock.acquire(timeout=MOVE_TIMEOUT):
            logging.warning("File move lock not acquired. Skipping.")
            return False

        if not os.path.exists(file_path):
            logging.warning(f"File does not exist anymore: {file_path}")
            return False

        filename = os.path.basename(file_path)
        destination_folder = os.path.abspath(os.path.expanduser(destination_folder))
        os.makedirs(destination_folder, exist_ok=True)
        destination_path = os.path.join(destination_folder, filename)

        # Resolve name conflicts by appending (1), (2), etc.
        count = 1
        while os.path.exists(destination_path):
            name, ext = os.path.splitext(filename)
            destination_path = os.path.join(destination_folder, f"{name} ({count}){ext}")
            count += 1

        shutil.move(file_path, destination_path)
        logging.info(f"📁 Moved '{filename}' to '{destination_folder}'")

        return os.path.exists(destination_path)

    except Exception as err:
        logging.error(f"Move operation failed: {err}")
        return False

    finally:
        move_lock.release()
# === FILE WATCHER ===
# This class responds to file events (creation, mostly) and handles sorting + duplicate checking

# Processes a batch of files from the queue
def process_batch():
    try:
        while not process_queue.empty():
            file_path, destination_folder = process_queue.get()
            move_file_to_category(file_path, destination_folder, batch=False)
    except Exception as e:
        logging.error(f"Error processing batch: {e}")

class FileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        path = event.src_path
        time.sleep(0.1)  # give the system a sec to settle
        
        if os.path.exists(path):
            filename = os.path.basename(path)
            executor.submit(self.handle_new_file, path, filename)

    def handle_new_file(self, file_path, file_name):
        try:
            # First try keyword sorting — if it matches, we’re done
            if sort_files_by_keywords(file_path, file_name):
                return

            # Otherwise, check for duplicates
            checksum = calculate_checksum(file_path)
            if checksum:
                for existing_path, (cached_hash, _) in file_hash_cache.items():
                    if checksum == cached_hash and os.path.exists(existing_path):
                        if is_file_older_than(file_path, minutes=1):
                            move_to_duplicates(
                                file_path, file_name,
                                os.path.expanduser("~/Duplicates")
                            )
                        return

                # Not a duplicate? Save hash for future
                file_hash_cache[file_path] = (checksum, time.time())

        except Exception as err:
            logging.error(f"Error handling new file {file_name}: {err}")
def update_timer():
    global next_emptying_time_2, next_scan_time
    now = datetime.now()

    if (next_emptying_time_2 - now).total_seconds() <= 0:
        empty_duplicates_folder()
        next_emptying_time_2 = now + timedelta(minutes=2)

    if (next_scan_time - now).total_seconds() <= 0:
        scan_for_duplicates()
        next_scan_time = now + timedelta(minutes=1)

    time_to_clean = str(next_emptying_time_2 - now).split('.')[0]
    time_to_scan = str(next_scan_time - now).split('.')[0]
    timer_label.config(text=f"Next Cleanup: {time_to_clean}\nNext Scan: {time_to_scan}")

    root.after(1000, update_timer)  # refresh every second
def launch_ui():
    global root, timer_label, current_directory

    root = Tk()
    root.title("Smart File Sorter")
    root.geometry("600x300")
    root.resizable(False, False)

    current_directory = StringVar()
    current_directory.set(os.path.expanduser("~"))

    Label(root, text="📂 Smart File Sorter", font=("Arial", 16)).pack(pady=10)

    timer_label = Label(root, text="", font=("Arial", 10))
    timer_label.pack(pady=5)

    Button(root, text="Run Scan Now", command=scan_for_duplicates).pack(pady=10)

    update_timer()
    root.mainloop()
# === DIRECTORY + FILE TREE SETUP ===
# This builds the side-by-side folder + file list and connects interactions

def build_file_browser_ui(parent_frame):
    global file_tree, directory_tree

    # Frame to hold left and right panes
    main_split = Frame(parent_frame)
    main_split.pack(fill=BOTH, expand=True)

    # LEFT: Directory tree
    dir_frame = Frame(main_split, bd=2, relief=GROOVE)
    dir_frame.pack(side=LEFT, fill=Y)

    Label(dir_frame, text="Folders").pack()

    directory_tree = ttk.Treeview(dir_frame)
    directory_tree.pack(fill=Y, expand=True)
    populate_directory_tree()

    directory_tree.bind("<<TreeviewSelect>>", on_directory_select)

    # RIGHT: Files in selected folder
    file_frame = Frame(main_split, bd=2, relief=GROOVE)
    file_frame.pack(side=RIGHT, fill=BOTH, expand=True)

    Label(file_frame, text="Files").pack()

    file_tree = ttk.Treeview(file_frame, columns=("Name", "Type", "Size"), show="headings")
    file_tree.heading("Name", text="Name")
    file_tree.heading("Type", text="Type")
    file_tree.heading("Size", text="Size")
    file_tree.pack(fill=BOTH, expand=True)

    file_tree.bind("<Button-3>", show_context_menu)
def populate_directory_tree():
    directory_tree.delete(*directory_tree.get_children())

    for path in specific_directories:
        display = os.path.basename(path) or path
        directory_tree.insert('', 'end', iid=path, text=display, values=[path])
def on_directory_select(event):
    try:
        selected = directory_tree.selection()
        if selected:
            selected_path = selected[0]
            current_directory.set(selected_path)
            update_file_view(selected_path)
    except Exception as e:
        logging.error(f"Error selecting directory: {e}")
def update_file_view(directory):
    try:
        file_tree.delete(*file_tree.get_children())
        files = os.listdir(directory)

        for fname in files:
            full_path = os.path.join(directory, fname)

            if os.path.isfile(full_path):
                ext = os.path.splitext(fname)[1]
                size = os.path.getsize(full_path) // 1024
                file_tree.insert('', 'end', values=(fname, ext, f"{size} KB"))

    except Exception as e:
        logging.error(f"Couldn't update file list for {directory}: {e}")
def show_context_menu(event):
    try:
        selected_item = file_tree.identify_row(event.y)
        if selected_item:
            file_tree.selection_set(selected_item)

        context_menu = Menu(root, tearoff=0)
        context_menu.add_command(label="Open", command=open_selected_file)
        context_menu.add_command(label="Delete", command=delete_selected_file)
        context_menu.tk_popup(event.x_root, event.y_root)
    except Exception as e:
        logging.error(f"Context menu failed: {e}")
def open_selected_file():
    selected = file_tree.focus()
    if not selected:
        return

    try:
        filename = file_tree.item(selected)["values"][0]
        folder = current_directory.get()
        full_path = os.path.join(folder, filename)
        os.startfile(full_path)
    except Exception as e:
        messagebox.showerror("Open File", f"Can't open file: {e}")

def delete_selected_file():
    selected = file_tree.focus()
    if not selected:
        return

    try:
        filename = file_tree.item(selected)["values"][0]
        folder = current_directory.get()
        full_path = os.path.join(folder, filename)

        confirm = messagebox.askyesno("Delete File", f"Send '{filename}' to Recycle Bin?")
        if confirm:
            send2trash.send2trash(full_path)
            update_file_view(folder)
    except Exception as e:
        messagebox.showerror("Delete File", f"Error deleting file: {e}")
# === FOLDER MANAGEMENT ===

def add_folder():
    path = simpledialog.askstring("Add Folder", "Enter folder path:")
    if not path:
        return

    abs_path = os.path.abspath(os.path.expanduser(path))
    if os.path.exists(abs_path) and abs_path not in specific_directories:
        specific_directories.append(abs_path)
        save_directories()
        populate_directory_tree()
    else:
        messagebox.showwarning("Add Folder", "Invalid or already added.")

def remove_selected_folder():
    selected = directory_tree.selection()
    if not selected:
        return

    folder_path = selected[0]
    confirm = messagebox.askyesno("Remove Folder", f"Remove {folder_path} from watch list?")
    if confirm and folder_path in specific_directories:
        specific_directories.remove(folder_path)
        save_directories()
        populate_directory_tree()

def save_directories():
    try:
        with open("directories.json", "w") as f:
            json.dump(specific_directories, f)
    except Exception as e:
        logging.error(f"Failed to save directory list: {e}")
def show_help_window():
    help_win = Toplevel(root)
    help_win.title("Help / Instructions")
    help_win.geometry("400x300")

    instructions = Text(help_win, wrap=WORD)
    instructions.insert(END, "📌 How Smart File Sorter Works:\n\n")
    instructions.insert(END, "- Files are automatically sorted into folders based on keywords.\n")
    instructions.insert(END, "- You can add/remove folders from the watch list.\n")
    instructions.insert(END, "- Duplicate files are moved to the ~/Duplicates folder temporarily.\n")
    instructions.insert(END, "- Every 2 minutes, the Duplicates folder is cleared (soft-deleted).\n")
    instructions.insert(END, "- Right-click files to open or delete them.\n\n")
    instructions.insert(END, "✅ Built with ❤️ and Tkinter.")
    instructions.config(state=DISABLED)
    instructions.pack(expand=True, fill=BOTH, padx=10, pady=10)
def create_menu_bar():
    menu_bar = Menu(root)

    # File menu
    file_menu = Menu(menu_bar, tearoff=0)
    file_menu.add_command(label="Add Folder", command=add_folder)
    file_menu.add_command(label="Remove Selected Folder", command=remove_selected_folder)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)
    menu_bar.add_cascade(label="File", menu=file_menu)

    # Help menu
    help_menu = Menu(menu_bar, tearoff=0)
    help_menu.add_command(label="Help", command=show_help_window)
    menu_bar.add_cascade(label="Help", menu=help_menu)

    root.config(menu=menu_bar)
def start_monitoring():
    observer = Observer()
    handler = FileHandler()

    for folder in specific_directories:
        if os.path.exists(folder):
            observer.schedule(handler, folder, recursive=False)

    observer.start()


if __name__ == "__main__":
    try:
        # Load saved timers (next scan, cleanup)
        load_timer_state()
        load_scan_timer_state()

        # Start monitoring in background
        start_monitoring()

        # Launch the GUI
        root = Tk()
        root.title("Smart File Sorter")
        root.geometry("800x500")

        current_directory = StringVar()
        current_directory.set(os.path.expanduser("~"))

        create_menu_bar()
        build_file_browser_ui(root)
        update_timer()
        root.mainloop()

    except Exception as e:
        logging.critical(f"App crashed: {e}")
