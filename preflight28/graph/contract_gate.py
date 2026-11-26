"""Check known Siso log-only output contracts before the long APK compilation."""
import os
import re
import stat
import subprocess

from android_outputs import verify_nominal_command, verify_nominal_sources
from graph import sha
from retained import ANDROID_RULES_SHA256, NOMINAL_GROUPS, NOMINAL_MATERIAL, NOMINAL_RULES, S2


# The archived S2 frontier records these four exact IDs as pending. Neither a
# later parent nor a different generated graph is subject to this initial check.
S2_GN = 'a553fc84a2cea62d5ef2beba03a0a8daba6e7e1d790132969f94221563ea5a5a'
S2_PENDING = {
    '03a93c620a4d86c3bc32838326098d383cac2c07911d70d81c31356cebbf430a',
    '436b8ea3b9a168b31eb81e7c595be3bf47c733715c121ea46b41d4b84efa8540',
    'b704bfcc2c9406830e2bd57f240a5e43dbadbc01d7ceb2ac439a5d421bf69caf',
    'c83bc64ae8b690a384831c80208566ca575385ece4b04c95443bd8b2b616e6ff',
}


def verify_pending_contract(out, planned, rules, *, parent_sha, graph):
    if parent_sha == S2 and graph == S2_GN:
        missing = S2_PENDING.difference(planned)
        if missing:
            raise ValueError('Pinned S2 initial plan lost known pending groups: ' + ', '.join(sorted(missing)))

    # The ordinary full-APK dry run already computed these groups and rules.
    selected = {}
    for edge, names in planned.items():
        record = rules.get(edge)
        if (not NOMINAL_MATERIAL.intersection(names)
                and (record is None or record[0] not in NOMINAL_RULES)):
            continue
        if record is None:
            raise ValueError('Pending log-only Android group lacks its planner rule: ' + edge)
        rule, primary, action = record
        if NOMINAL_GROUPS.get(primary) != (rule, tuple(sorted(names))) or action in selected:
            raise ValueError('Unreviewed pending Android output group: ' + edge)
        if os.path.lexists(out / (primary + '.md5.stamp')):
            raise ValueError('Unexpected physical file at pending report-only output: ' + edge)
        if rule == 'android/errorprone' and os.path.lexists(out / primary):
            # This exact generator touches the marker; it cannot clear stale bytes.
            marker = (out / primary).lstat()
            if not stat.S_ISREG(marker.st_mode) or marker.st_size != 0:
                raise ValueError('Pending Error Prone marker is not an empty regular file: ' + edge)
        selected[action] = (edge, rule, primary, names)
    if not selected:
        return 0

    src = out.parent.parent
    if sha(src / 'build/config/siso/android.star') != ANDROID_RULES_SHA256:
        raise ValueError('Pending Android output handler changed')
    verify_nominal_sources(src, (row[1] for row in selected.values()))

    # Siso loads the GN manifests once and prints just the selected rules.
    # It does not plan the APK again or run any generator.
    siso = src / 'third_party/siso/cipd/siso'
    try:
        result = subprocess.run([siso, 'query', 'rule', '-C', str(out),
                                 *(row[2] for row in selected.values())],
                                cwd=src, stdout=subprocess.PIPE, check=True, timeout=90)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError('Could not read the pending Android GN rules') from exc
    commands = re.findall(r'^rule (\S+)\n  command = ([^\n]+)$', result.stdout.decode(), re.MULTILINE)
    if len(commands) != len(selected) or set(selected) != {action for action, _ in commands}:
        raise ValueError('GN and current Android planner actions differ')
    for graph_action, raw_command in commands:
        edge, rule, primary, names = selected[graph_action]
        # These four exact rules contain only the Ninja colon escape. Additional
        # variables/escapes cannot inherit a command's previously reviewed identity.
        command = raw_command.replace('$:', ':')
        if '$' in command:
            raise ValueError('Unsupported pending Android GN command expansion: ' + edge)
        try:
            verify_nominal_command(src, rule, primary, names, command,
                                   rules[edge][2], graph_action)
        except ValueError as exc:
            raise ValueError('Pending Android generator command differs: ' + edge) from exc
    return len(selected)
