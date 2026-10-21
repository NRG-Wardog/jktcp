"""Verify the exact reviewed jktcp 0.1.8 owner source, without runtime patchers.

This baseline intentionally includes reviewed upstream behavior changes. It does
not claim byte equality with the previous generated-source migration. The caller
must bind this manifest/verifier and the selected commit in its exact-pin contract.
No Rust code, native fixture, or device operation is executed by this verifier.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message="source parity failed"):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_NO_REPLACE_OBJECTS="1", GIT_GRAFT_FILE=os.devnull,
        GIT_NO_LAZY_FETCH="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
    )
    return subprocess.check_output(
        ["git", "-c", "advice.graftFileDeprecated=false", "--no-replace-objects",
         "-C", str(ROOT), "--work-tree", str(ROOT), *args], env=env,
    )


def inventory(rev):
    result = {}
    for row in git("ls-tree", "-rz", rev).split(b"\x00"):
        if row:
            metadata, path = row.split(b"\t")
            mode, kind, oid = metadata.decode().split()
            result[path.decode()] = (mode, kind, oid)
    return result


def entries(spec):
    rows = spec["files"]
    result = {r["path"]: r for r in rows}
    require(len(rows) == len(result), "duplicate product path")
    metadata = spec["metadata_files"]
    require(len(metadata) == len(set(metadata)), "duplicate metadata path")
    require(not (set(result) & set(metadata)), "product/metadata overlap")
    for name in set(result) | set(metadata):
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts
                and name == path.as_posix() and name not in ("", ".", ".git")
                and not name.startswith(".git/"), "unsafe inventory path")
    return result


def verify_committed(spec, actual, original, previous, blob):
    products = entries(spec)
    require(set(original) == set(products), "upstream product inventory mismatch")
    require(set(actual) == set(products) | set(spec["metadata_files"]),
            "unexpected committed inventory")
    for name, row in products.items():
        mode, kind, oid = actual[name]
        require(kind == "blob" and mode == row["git_mode"], name + " source mode/type mismatch")
        require(oid == row["new_source_blob"], name + " source blob mismatch")
        require(digest(blob(oid)) == row["new_source_sha256"], name + " frozen source mismatch")
        old_mode, old_kind, old_oid = original[name]
        require((old_mode, old_kind, old_oid) ==
                (row["upstream_git_mode"], "blob", row["upstream_blob"]),
                name + " upstream entry mismatch")
        require(digest(blob(old_oid)) == row["upstream_sha256"], name + " upstream hash mismatch")
        prior = previous.get(name)
        if row["previous_owner_blob"] is None:
            require(prior is None, name + " unexpected previous source")
        else:
            require(prior == (row["previous_owner_git_mode"], "blob", row["previous_owner_blob"]),
                    name + " previous entry mismatch")
            require(digest(blob(prior[2])) == row["previous_owner_sha256"],
                    name + " previous hash mismatch")
    for name in spec["metadata_files"]:
        require(actual[name][0:2] == ("100644", "blob"), name + " unsafe metadata mode/type")
    return len(products)


def verify_worktree(root, actual, blob):
    for name, (mode, kind, oid) in actual.items():
        require(kind == "blob", name + " unsupported tracked type")
        path = root / name
        content = blob(oid)
        if mode == "120000":
            require(path.is_symlink() and os.readlink(path).encode() == content,
                    name + " symlink drift")
        else:
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode), name + " unsafe file type")
            require(("100755" if info.st_mode & 0o111 else "100644") == mode,
                    name + " mode drift")
            require(path.read_bytes() == content, name + " worktree drift")
    files = set()
    for directory, dirs, names in os.walk(root, followlinks=False):
        rel = Path(directory).relative_to(root)
        if rel == Path("."):
            dirs[:] = [name for name in dirs if name != ".git"]
            names = [name for name in names if name != ".git"]
        for name in list(dirs):
            if (Path(directory) / name).is_symlink():
                files.add((rel / name).as_posix())
                dirs.remove(name)
        files.update((rel / name).as_posix() for name in names)
    require(files == set(actual), "unexpected filesystem inventory")


def verify():
    spec = json.loads((ROOT / ".ci/source-parity.json").read_text())
    require(spec["schema_version"] == 2, "unsupported baseline schema")
    require(git("rev-parse", "--is-shallow-repository").strip() == b"false", "shallow source history")
    parents = spec["upstream_sync"]["expected_merge_parents"]
    require(parents == [spec["previous_fork_commit"], spec["upstream_base"]], "invalid merge contract")
    head_line = git("rev-list", "--parents", "-n", "1", "HEAD").decode().split()
    require(head_line[1:] == parents, "unexpected owner merge parents")
    for parent in parents:
        git("merge-base", "--is-ancestor", parent, "HEAD")
    require(git("merge-base", *parents).decode().strip() == spec["upstream_sync"]["from_base"],
            "unexpected common ancestor")
    actual = inventory("HEAD")
    count = verify_committed(
        spec, actual, inventory(spec["upstream_base"]), inventory(spec["previous_fork_commit"]),
        lambda oid: git("cat-file", "blob", oid),
    )
    verify_worktree(ROOT, actual, lambda oid: git("cat-file", "blob", oid))
    return {
        "owner": spec["owner"], "status": "exact_reviewed_source_pass",
        "upstream_base": spec["upstream_base"], "fork_commit": head_line[0],
        "product_files_verified": count, "metadata_files_verified": len(spec["metadata_files"]),
        "merge_parents": parents, "behavior_changes": spec["behavior_differences"],
        "native_execution": False,
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
