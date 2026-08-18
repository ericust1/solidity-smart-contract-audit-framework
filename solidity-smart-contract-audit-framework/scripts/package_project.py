import os
import sys
import zipfile
from pathlib import Path


def package_project():
    project_root = Path(__file__).parent.parent
    dist_dir = project_root / "dist"
    dist_dir.mkdir(exist_ok=True)

    zip_name = f"{project_root.name}.zip"
    zip_path = dist_dir / zip_name

    excluded = {"__pycache__", ".pyc", "node_modules", ".git", "artifacts", "cache", "dist"}

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(project_root):
            dirs[:] = [d for d in dirs if d not in excluded]
            for file in files:
                if file.endswith(".pyc"):
                    continue
                full_path = Path(root) / file
                arc_path = full_path.relative_to(project_root)
                zf.write(full_path, arc_path)

    size = zip_path.stat().st_size
    print(f"Packaged to {zip_path} ({size:,} bytes)")
    return str(zip_path)


if __name__ == "__main__":
    package_project()
