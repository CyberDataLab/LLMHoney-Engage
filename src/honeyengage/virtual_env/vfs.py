"""In-memory virtual file system of the emulated host."""

import copy
import functools
import json
import os
import posixpath
from typing import Any

from loguru import logger

from src.honeyengage.virtual_env.cowrie.shell.fs import FileNotFound

logger.add("logs/honeyengage_vfs.log", rotation="10 MB")


@functools.lru_cache(maxsize=8)
def _load_filesystem_json(json_path: str) -> dict | None:
  if not os.path.exists(json_path):
    return None
  with open(json_path, encoding="utf-8") as f:
    return json.load(f)

class FSNode:
  def __init__(self, name: str, uid: int = 0, gid: int = 0, size: int = 4096, permissions: str = "rwxr-xr-x"):
    self.name = name
    self.uid = uid
    self.gid = gid
    self.size = size
    self.permissions = permissions
  
class FSDirectory(FSNode):
  def __init__(self, name: str, **kwargs):
    super().__init__(name, **kwargs)
    self.children: dict[str, FSNode] = {}

  def add_child(self, child: FSNode):
    self.children[child.name] = child
  
class FSFile(FSNode):
  def __init__(self, name: str, path=None, content="", **kwargs):
    super().__init__(name, **kwargs)
    self.path = path
    self.content = content
  
  def read_honeyfs_contents(self):
    honeyfs_path = os.path.join("honeyfs", self.path) if self.path else None
    if honeyfs_path and os.path.exists(honeyfs_path):
      with open(honeyfs_path, encoding='utf-8') as f:
        return f.read()
    return ""

class VirtualFileSystem:
  def __init__(self, json_path="src/honeyengage/virtual_env/filesystem.json", honeyfs_path="honeyfs"):
    self.root: FSDirectory = FSDirectory("/")
    self.current_directory: FSDirectory = self.root
    self.cwd_path: str = "/"
    self.honeyfs_path = honeyfs_path

    self.load_from_json(json_path)
  
  def load_from_json(self, json_path: str):
    cached_data = _load_filesystem_json(json_path)
    if cached_data is None:
      logger.error(f"Filesystem JSON file not found: {json_path}")
      return

    data = copy.deepcopy(cached_data)
    parsed_root = self._parse_node(data)
    if not isinstance(parsed_root, FSDirectory):
      logger.error(f"Root node in {json_path} is not a directory. Keeping previous filesystem.")
      return
    self.root = parsed_root

    self._set_initial_directory("/root")
    logger.success("Filesystem loaded successfully.")

  def _parse_node(self, node_data: dict) -> FSNode:
    node: FSNode
    if node_data["type"] == "directory":
      directory = FSDirectory(
        name=node_data["name"],
        uid=node_data.get("uid", 0),
        gid=node_data.get("gid", 0),
        size=node_data.get("size", 4096),
        permissions=node_data.get("permissions", "drwxr-xr-x")
      )

      for child_data in node_data.get("children", {}).values():
        directory.add_child(self._parse_node(child_data))
      node = directory

    else:
      node = FSFile(
        name=node_data["name"],
        uid=node_data.get("uid", 0),
        gid=node_data.get("gid", 0),
        size=node_data.get("size", 0),
        permissions=node_data.get("permissions", "-rw-r--r--"),
      )
    return node
  
  def _set_initial_directory(self, target_path: str):
    if target_path == "/root" and "root" in self.root.children:
      root_dir = self.root.children["root"]
      if isinstance(root_dir, FSDirectory):
        self.current_directory = root_dir
        self.cwd_path = "/root"
      else:
        logger.error("Expected 'root' to be a directory in the filesystem JSON.")
    else:
      logger.warning(f"Initial directory {target_path} not found. Starting at root.")
      self.current_directory = self.root
      self.cwd_path = "/"
  
  def list_directory(self, path: str):
    abs_path_str = self.resolve_path(path, self.cwd_path)
    node = self.get_node(abs_path_str)
    if node and isinstance(node, FSDirectory):
      return "  ".join(node.children.keys())
    elif node:
      return node.name + "\r\n"
    else:
      return f"ls: cannot access {path}: No such file or directory\r\n"

  def resolve_path(self, path: str, cwd: str):
    return posixpath.normpath(posixpath.join(cwd, path))

  def get_node(self, path: str):
    node: FSNode
    if path == "/":
      return self.root
    
    parts = path.strip("/").split("/")
    node = self.root
    for part in parts:
      if isinstance(node, FSDirectory) and part in node.children:
        node = node.children[part]
      else:
        return None
    return node
  
  def delete_node(self, path: str) -> bool:
    if path == "/":
      return False
    
    parts = path.strip("/").split("/")
    parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    node_name = parts[-1]

    parent_node = self.get_node(parent_path)
    if parent_node and isinstance(parent_node, FSDirectory) and node_name in parent_node.children:
      del parent_node.children[node_name]
      return True
    return False

  def file_contents(self, virtual_path: str) -> bytes:
    if virtual_path.endswith("/proc/meminfo"):
      return (
        b"MemTotal:        2010780 kB\n"
        b"MemFree:         1451796 kB\n"
        b"MemAvailable:    1638988 kB\n"
        b"Buffers:           23944 kB\n"
        b"Cached:           286820 kB\n"
        b"SwapTotal:       2097148 kB\n"
        b"SwapFree:        2097148 kB\n"
      )
    base_path = os.path.abspath(self.honeyfs_path)
    honeyfs_path = os.path.join(base_path, virtual_path.lstrip("/"))
    if os.path.exists(honeyfs_path) and os.path.isfile(honeyfs_path):
      with open(honeyfs_path, 'rb') as f:
        content = f.read()
        return content.replace(b"\r\n", b"\n")
    
    node = self.get_node(virtual_path)
    if node and isinstance(node, FSFile):
      return node.content.encode('latin-1')

    raise FileNotFound(virtual_path)

  def listdir(self, virtual_path: str) -> list[str]:
    node = self.get_node(virtual_path)
    if node and isinstance(node, FSDirectory):
      return list(node.children.keys())
    else:
      raise FileNotFound(virtual_path)

  def override_file_contents(self, virtual_path: str, new_content: bytes):
    node = self.get_node(virtual_path)
    if node and isinstance(node, FSFile):
      node.content = new_content.decode('latin-1')
      return True
    return False

  def override_file_metadata(self, virtual_path: str, new_metadata: dict[str, Any]):
    node = self.get_node(virtual_path)
    if node:
      node.name = new_metadata.get("name", node.name)
      node.uid = new_metadata.get("uid", node.uid)
      node.gid = new_metadata.get("gid", node.gid)
      node.size = new_metadata.get("size", node.size)
      if "permissions" in new_metadata or "mode" in new_metadata:
        raw_value = new_metadata["permissions"] if "permissions" in new_metadata else new_metadata["mode"]
        node.permissions = self._coerce_permissions(raw_value, node.permissions)
      return True
    return False

  @staticmethod
  def _coerce_permissions(value: Any, fallback: str) -> str:
    if isinstance(value, str) and len(value) == 10:
      return value
    if isinstance(value, int):
      octal = value if value <= 0o777 else int(str(value), 8)
      bits = "".join(
        ("r" if octal & mask_r else "-") + ("w" if octal & mask_w else "-") + ("x" if octal & mask_x else "-")
        for mask_r, mask_w, mask_x in ((0o400, 0o200, 0o100), (0o040, 0o020, 0o010), (0o004, 0o002, 0o001))
      )
      type_char = fallback[0] if fallback else "-"
      return type_char + bits
    return fallback
  

  def exists(self, path: str):
    return self.get_node(path) is not None

  def isdir(self, path: str):
    node = self.get_node(path)
    return node is not None and isinstance(node, FSDirectory)

  def isfile(self, path: str):
    node = self.get_node(path)
    return node is not None and isinstance(node, FSFile)
  
  def mkdir(self, path: str, uid: int, gid: int, size: int, mode: str):
    import posixpath
    parent_dir_path = posixpath.dirname(path)
    new_dir_name = posixpath.basename(path)
    
    parent_node = self.get_node(parent_dir_path)
    
    if parent_node and isinstance(parent_node, FSDirectory):
      new_node = FSDirectory(new_dir_name, uid=uid, gid=gid, size=size, permissions=mode)
      parent_node.add_child(new_node)
      return True
    return False
  
  def mkfile(self, path: str, uid: int, gid: int, size: int, mode: str, realfile=None):
    import posixpath
    parent_dir_path = posixpath.dirname(path)
    new_file_name = posixpath.basename(path)
    
    parent_node = self.get_node(parent_dir_path)
    
    if parent_node and isinstance(parent_node, FSDirectory):
      new_node = FSFile(new_file_name, uid=uid, gid=gid, size=size, permissions=mode, path=realfile)
      parent_node.add_child(new_node)
      return True
    return False

  def _ensure_directory_path(self, path: str, uid: int, gid: int, size: int = 4096, mode: str = "drwxr-xr-x"):
    normalized_path = posixpath.normpath(path)

    if normalized_path in ("", ".", "/"):
      return self.root

    parts = normalized_path.strip("/").split("/")
    current_node: FSDirectory = self.root

    for part in parts:
      next_node = current_node.children.get(part)

      if next_node is None:
        next_node = FSDirectory(part, uid=uid, gid=gid, size=size, permissions=mode)
        current_node.add_child(next_node)
      elif not isinstance(next_node, FSDirectory):
        return None

      current_node = next_node

    return current_node

  def mkdir_p(self, path: str, uid: int, gid: int, size: int, mode: str):
    import posixpath

    normalized_path = posixpath.normpath(path)
    if normalized_path == "/":
      return True

    parent_dir_path = posixpath.dirname(normalized_path)
    new_dir_name = posixpath.basename(normalized_path)

    parent_node = self._ensure_directory_path(parent_dir_path, uid, gid)
    if parent_node and isinstance(parent_node, FSDirectory):
      existing_node = parent_node.children.get(new_dir_name)
      if existing_node is not None:
        return isinstance(existing_node, FSDirectory)

      new_node = FSDirectory(new_dir_name, uid=uid, gid=gid, size=size, permissions=mode)
      parent_node.add_child(new_node)
      return True

    return False

  def mkfile_p(self, path: str, uid: int, gid: int, size: int, mode: str, realfile=None):
    import posixpath

    normalized_path = posixpath.normpath(path)
    parent_dir_path = posixpath.dirname(normalized_path)
    new_file_name = posixpath.basename(normalized_path)

    parent_node = self._ensure_directory_path(parent_dir_path, uid, gid)
    if parent_node and isinstance(parent_node, FSDirectory):
      existing_node = parent_node.children.get(new_file_name)
      if existing_node is not None:
        return isinstance(existing_node, FSFile)

      new_node = FSFile(new_file_name, uid=uid, gid=gid, size=size, permissions=mode, path=realfile)
      parent_node.add_child(new_node)
      return True

    return False