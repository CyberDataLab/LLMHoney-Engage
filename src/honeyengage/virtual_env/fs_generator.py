"""Exports the file system of a clean Ubuntu image to the JSON used by the emulated host."""

import json
import os
import stat


def get_permissions(mode):
  return stat.filemode(mode)

def build_tree(root_path):
  tree = {
    "name": os.path.basename(root_path) or "/",
    "type": "directory",
    "children": {}
  }

  try:
    for entry in os.scandir(root_path):
      if entry.path in ["/proc", "/sys", "/dev", "/run", "/mnt"]:
        continue

      try:
        stat_res = entry.stat(follow_symlinks=False)
        node = {
          "name": entry.name,
          "uid": stat_res.st_uid,
          "gid": stat_res.st_gid,
          "size": stat_res.st_size,
          "permissions": get_permissions(stat_res.st_mode)
        }

        if entry.is_dir(follow_symlinks=False):
          node["type"] = "directory"
          node["children"] = build_tree(entry.path)["children"]
        else:
          node["type"] = "file"
          node["content"] = ""
          node["path"] = entry.path
        
        tree["children"][entry.name] = node

      except PermissionError:
        pass
      except FileNotFoundError:
        pass

  except PermissionError:
    pass

  return tree

if __name__ == "__main__":
  print("Building filesystem tree...")
  root_path = "/"
  filesystem_tree = build_tree(root_path)
  output_file = "filesystem.json"
  with open(output_file, "w", encoding="utf-8") as f:
    json.dump(filesystem_tree, f, indent=2)
  print(f"Filesystem tree saved to {output_file}")