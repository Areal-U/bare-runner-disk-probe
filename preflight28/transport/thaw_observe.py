"""Run the original dry recovery recipe with the three observer logs kept outside its subject."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

HEAD = "81105d5f7b9ba994034753ce4fbd65d9b981dde3"
PRODUCER_RECIPE = "783470cd9d8c17f6d14a9c81fec1fecadf746e04450dee2b3980a3fc96f3faa4"
START = 'read_mode=()\n[[ $R28_ROLE != receive ]] || read_mode=(-n)'
END = 'proof=out/Bare/checkpoint-round28-graph.json'
GRAPH_CHECK = '  python3 /exchange/graph.py receive --out out/Bare --proof "$proof"'
OBSERVE = '''[[ $R28_ROLE == receive ]]
subject="$PWD/out/Bare"
observer=$(mktemp -d "$PWD/out/.r28-dry-observer-XXXXXXXX")
mkdir "$observer/state" "$observer/logs"
track_original_state() (
  cd "$subject"
  shopt -s nullglob
  for file in .siso_* .ninja_* siso_metrics*.json; do
    [[ -f $file && ! -L $file ]]
    sha256sum -- "$file"
  done
)
(
track_original_state > "$observer/before"
extra=$(stat -c %s -- "$subject/.ninja_log")
for file in .siso_deps .siso_fs_state .siso_fs_state.journal; do
  if [[ -f $subject/$file ]]; then extra=$(( extra + $(stat -c %s -- "$subject/$file") )); fi
done
available=$(df -B1 --output=avail "$subject" | tail -1)
inodes=$(df -Pi "$subject" | awk 'NR==2 {print $4}')
(( available >= 20 * 1024**3 + 64 * 1024**2 + extra && inodes >= 20032 ))
echo "dry_observer_initial_free_bytes=$((available)) state_copy_bytes=$extra available_inodes=$inodes"
for file in .siso_deps .siso_fs_state .siso_fs_state.journal; do
  if [[ -f $subject/$file ]]; then
    cp -p -- "$subject/$file" "$observer/state/$file"
  fi
done
[[ -f $subject/.ninja_log && ! -L $subject/.ninja_log ]]
mv -T -- "$subject/.ninja_log" "$observer/original-ninja-log"
restore_original_log() {
  mv -fT -- "$observer/original-ninja-log" "$subject/.ninja_log"
}
trap restore_original_log EXIT
cp -p -- "$observer/original-ninja-log" "$subject/.ninja_log"
read_mode=(-n -metrics_json "$observer/metrics.jsonl" -state_dir "$(realpath --relative-to="$subject" "$observer/state")" -log_dir "$observer/logs")
'''
FINISH = '''restore_original_log
trap - EXIT
track_original_state > "$observer/after"
cmp -- "$observer/before" "$observer/after"
echo "dry_reuse_observers=3 original_ninja_siso_state_and_metrics=unchanged"
)
'''
AFTER_GRAPH = '''track_original_state > "$observer/final"
cmp -- "$observer/before" "$observer/final"
[[ $observer == "$PWD/out/.r28-dry-observer-"* && -d $observer && ! -L $observer ]]
rm -r -- "$observer"
echo "original_ninja_siso_state_and_metrics_after_apk_plan=unchanged"
'''


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def observed_recipe(script):
    if (sha(script) != PRODUCER_RECIPE or script.count(START) != 1 or script.count(END) != 1 or script.count(GRAPH_CHECK) != 1
            or script.count('autoninja "${read_mode[@]}" -C out/Bare -j 2 -v ') != 3):
        raise ValueError("Unrecognized original receiver recipe")
    return (script.replace(START, OBSERVE, 1).replace(END, FINISH + END, 1)
            .replace(GRAPH_CHECK, GRAPH_CHECK + "\n" + AFTER_GRAPH, 1))


def main():
    tree=Path(os.environ["THAW_SOURCE_TREE"]).resolve(strict=True)
    if (os.environ["GITHUB_JOB"]!="receive" or os.environ["GITHUB_REPOSITORY"]!="Areal-U/bare-runner-disk-probe"
            or os.environ["TRIAL_SHA"]!=HEAD or Path(os.environ["GITHUB_WORKSPACE"]).resolve()!=tree
            or Path.cwd().resolve()!=tree or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
            or subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()!=HEAD):
        raise ValueError("Wrong original receiver or credentials present")
    sys.path.insert(0,str(tree/"preflight28/transport"))
    import prepare
    if Path(prepare.__file__).resolve()!=tree/"preflight28/transport/prepare.py":
        raise ValueError("Unrecognized original receiver module")
    original_shell=prepare.shell
    used=False

    def run(script, *, label="fixed setup step", **env):
        nonlocal used
        if label=="S2 receive":
            if used or env.get("R28_ROLE")!="receive" or env.get("INPUT_REVISION")!=HEAD:
                raise ValueError("Observer may execute only on the single original readback")
            script=observed_recipe(script)
            print(f"producer_recipe_sha256={PRODUCER_RECIPE} effective_readonly_recipe_sha256={sha(script)}",flush=True)
            used=True
        original_shell(script,label=label,**env)
    prepare.shell=run
    # setup() validates SHA/identity and records the ORIGINAL producer environment
    # and original recipe. Only this separate receiver's zero-step observer is redirected.
    prepare.setup("receive")
    if not used:
        raise ValueError("Original readback was not observed")


if __name__=="__main__":
    main()
