#!/usr/bin/env python3
"""Prepare and publish a narsil-xref release; --dry-run changes nothing."""

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Branch every release is cut from and published from.
RELEASE_BRANCH = 'main'

REMOTE = 'origin'

# The package and binary name in Cargo.toml.
PACKAGE = 'narsil-xref'

# The "name:" line of the workflow files under .github/workflows.
CI_WORKFLOW = 'CI'
RELEASE_WORKFLOW = 'Release'

# CI_FEATURES of ci.yml, used by its second clippy run and its tests.
CI_FEATURES = 'native'

# One entry per build in build-binaries.yml: the artifact name its tarball
# carries and the architecture name cargo-deb puts in the .deb file name.
ARCHITECTURES = [
    {'tarball_arch': 'linux-x86_64', 'deb_arch': 'amd64'},
    {'tarball_arch': 'linux-aarch64', 'deb_arch': 'arm64'},
]

# cargo-deb appends this revision to the package version in the .deb name.
DEB_REVISION = '1'

# How long publish waits for the Release run to show up after the tag push.
RUN_APPEARS_SECONDS = 180
RUN_POLL_SECONDS = 5

# release.yml starts on tags v[0-9]+.*, so a version starts with digits.
VERSION_PATTERN = re.compile(r'^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$')

# A released changelog heading, such as "## [1.7.0] - 2026-05-12".
RELEASED_HEADING = re.compile(r'^## \[[^\]]+\] - \d{4}-\d{2}-\d{2}\s*$')

CHANGELOG_HEADING_START = '## ['

# What publish does with the remote tag, from remote_tag_decision().
TAG_CREATE = 'create'
TAG_REUSE = 'reuse'
TAG_CONFLICT = 'conflict'


def fail(message):
    """Print why the release stops and leave with a non-zero status."""
    print('release.py: ' + message, file=sys.stderr)
    sys.exit(1)


def shown(argv):
    """Return a command as a shell would have to be given it."""
    return shlex.join(argv)


def run(argv):
    """Run a command in the checkout, showing it first; fail when it fails."""
    print('+ ' + shown(argv), flush=True)
    done = subprocess.run(argv, cwd=REPO_ROOT)
    if done.returncode != 0:
        fail('%s exited with status %d' % (argv[0], done.returncode))


def output(argv):
    """Run a command in the checkout and return its stdout minus the last newline."""
    done = subprocess.run(argv, cwd=REPO_ROOT, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    if done.returncode != 0:
        fail('%s failed: %s' % (shown(argv), done.stderr.strip()))
    return done.stdout.rstrip('\n')


def succeeds(argv):
    """Return whether a command in the checkout exits zero, its output dropped."""
    done = subprocess.run(argv, cwd=REPO_ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    return done.returncode == 0


def act(dry_run, argv):
    """Run a command that changes something; a dry run only shows it."""
    if dry_run:
        print('would run: ' + shown(argv))
        return
    run(argv)


def announce(dry_run, text):
    """Show a step that is not a command, such as a file edit."""
    if dry_run:
        print('would do: ' + text)
    else:
        print('+ ' + text, flush=True)


def git(*args):
    """Return the stdout of a git command run in the checkout."""
    # *args collects the positional arguments into a tuple.
    argv = ['git']
    for arg in args:
        argv.append(arg)
    return output(argv)


def gh_json(*args):
    """Return the parsed JSON a gh command prints."""
    argv = ['gh']
    for arg in args:
        argv.append(arg)
    text = output(argv)
    try:
        return json.loads(text)
    except ValueError:
        fail('%s did not print JSON: %s' % (shown(argv), text))


def require_tools(names):
    """Fail unless every program in names is installed, naming all that are not.

    Naming them all saves a second round after the first one is installed.
    """
    missing = []
    for name in names:
        if shutil.which(name) is None:
            missing.append(name)
    if len(missing) > 0:
        fail('not installed: ' + ', '.join(missing))


def require_clean_worktree():
    """Fail unless the checkout has no modified tracked file.

    "git commit -a" would otherwise put that file in the release commit.
    """
    status = git('status', '--porcelain', '--untracked-files=no')
    if status != '':
        fail('the working tree has uncommitted changes:\n' + status)


def require_valid_version(version):
    """Fail unless version is X.Y.Z or X.Y.Z-suffix, which release.yml tags."""
    if VERSION_PATTERN.match(version) is None:
        fail('"%s" is not a version like 2.1.0 or 2.1.0-rc1' % version)


def tag_name(version):
    """Return the git tag release.yml expects for a version."""
    return 'v' + version


def local_tag_commit(tag):
    """Return the commit a local tag names, empty when there is no such tag."""
    ref = 'refs/tags/' + tag + '^{commit}'
    if not succeeds(['git', 'rev-parse', '-q', '--verify', ref]):
        return ''
    return git('rev-parse', ref)


def ls_remote_rows(*patterns):
    """Return the commit the remote has each matching ref at, keyed by ref name.

    This asks the remote and fetches nothing, so a dry run changes nothing.
    """
    rows = {}
    for line in git('ls-remote', REMOTE, *patterns).splitlines():
        commit, ref = line.split('\t')
        rows[ref] = commit
    return rows


def remote_tag_commit(tag):
    """Return the commit the remote has a tag at, empty when it has none.

    The "^{}" row is asked for because an annotated tag otherwise reports its
    own object, which is never the commit it names.
    """
    ref = 'refs/tags/' + tag
    rows = ls_remote_rows(ref, ref + '^{}')
    peeled = rows.get(ref + '^{}')
    if peeled is not None:
        return peeled
    plain = rows.get(ref)
    if plain is not None:
        return plain
    return ''


def remote_branch_commit(branch):
    """Return the commit the remote has a branch at, empty when it has none."""
    ref = 'refs/heads/' + branch
    commit = ls_remote_rows(ref).get(ref)
    if commit is None:
        return ''
    return commit


def remote_tag_decision(remote_commit, head_commit):
    """Return TAG_CREATE, TAG_REUSE or TAG_CONFLICT for the tag publish wants.

    An empty remote_commit means the remote has no such tag.  TAG_REUSE is a
    tag the remote has at head_commit, left by an earlier publish that stopped
    after the push.
    """
    if remote_commit == '':
        return TAG_CREATE
    if remote_commit == head_commit:
        return TAG_REUSE
    return TAG_CONFLICT


def is_table_header(stripped_line):
    """Return whether a stripped Cargo.toml line opens a [table]."""
    return stripped_line.startswith('[')


def version_in_cargo_toml(text):
    """Return the version the [package] table of a Cargo.toml text declares."""
    in_package = False
    for line in text.splitlines():
        stripped = line.strip()
        if is_table_header(stripped):
            in_package = (stripped == '[package]')
            continue
        if not in_package:
            continue
        match = re.match(r'^version\s*=\s*"([^"]+)"', stripped)
        if match is not None:
            return match.group(1)
    fail('Cargo.toml has no version line under [package]')


def set_version_in_cargo_toml(text, version):
    """Return a Cargo.toml text with the [package] version replaced."""
    in_package = False
    lines = text.splitlines(keepends=True)
    for index in range(len(lines)):
        stripped = lines[index].strip()
        if is_table_header(stripped):
            in_package = (stripped == '[package]')
            continue
        if not in_package:
            continue
        match = re.match(r'^(\s*version\s*=\s*")([^"]+)(".*)$', lines[index],
                         re.DOTALL)
        if match is not None:
            lines[index] = match.group(1) + version + match.group(3)
            return ''.join(lines)
    fail('Cargo.toml has no version line under [package]')


def is_released_heading(line):
    """Return whether a changelog line heads a dated, released section."""
    return RELEASED_HEADING.match(line) is not None


def find_open_heading(lines):
    """Return the line index of the open changelog section, -1 when none is open.

    The open section is the first "## [" heading, whatever its title
    ("Unreleased", "Next", a bare version).  When that heading has a date, the
    newest release is closed already and no section is open.
    """
    for index in range(len(lines)):
        if not lines[index].startswith(CHANGELOG_HEADING_START):
            continue
        if is_released_heading(lines[index]):
            return -1
        return index
    return -1


def changelog_heading(version, today):
    """Return the heading of a released section: "## [2.1.0] - 2026-11-22"."""
    return '## [%s] - %s' % (version, today)


def close_changelog(text, version, today):
    """Return a changelog text with its open section renamed to a release."""
    lines = text.split('\n')
    index = find_open_heading(lines)
    if index < 0:
        fail('CHANGELOG.md has no open section: its first "## [" heading is '
             'a dated release')
    lines[index] = changelog_heading(version, today)
    return '\n'.join(lines)


def changelog_section(text, version):
    """Return the body of one version's changelog section, heading excluded.

    Fails when the section is absent or has no text, so a release never goes
    out with empty notes.
    """
    lines = text.splitlines()
    start_prefix = '## [' + version + ']'
    start = -1
    for index in range(len(lines)):
        if lines[index].startswith(start_prefix):
            start = index + 1
            break
    if start < 0:
        fail('CHANGELOG.md has no section for ' + version)
    end = len(lines)
    for index in range(start, len(lines)):
        if lines[index].startswith(CHANGELOG_HEADING_START):
            end = index
            break
    body = '\n'.join(lines[start:end]).strip('\n')
    if body == '':
        fail('the CHANGELOG.md section of %s is empty' % version)
    return body + '\n'


def expected_assets(version):
    """Return every file name the Release workflow uploads for a version.

    Each tarball and each .deb comes with a .sha256 file of the same name.
    """
    # cargo-deb writes a pre-release "-rc1" as "~rc1" in the .deb version.
    deb_version = version.replace('-', '~')
    names = []
    for arch in ARCHITECTURES:
        tarball = '%s-v%s-%s.tar.gz' % (PACKAGE, version, arch['tarball_arch'])
        deb = '%s_%s-%s_%s.deb' % (PACKAGE, deb_version, DEB_REVISION,
                                   arch['deb_arch'])
        names.append(tarball)
        names.append(tarball + '.sha256')
        names.append(deb)
        names.append(deb + '.sha256')
    return names


def missing_assets(expected, present):
    """Return the names in expected that present lacks, in expected order."""
    missing = []
    for name in expected:
        found = False
        for have in present:
            if have == name:
                found = True
                break
        if not found:
            missing.append(name)
    return missing


def ci_verdict(runs):
    """Return (passed, reason) for the CI runs of one commit.

    runs is the list "gh run list --json conclusion,status" prints.  A rerun
    leaves older failed runs of the same commit behind, so one success is
    enough.
    """
    if len(runs) == 0:
        return False, ('no CI run exists for HEAD; wait for it to start, or '
                       'enable Actions on the fork')
    unfinished = 0
    conclusions = []
    for run_info in runs:
        if run_info.get('status') != 'completed':
            unfinished += 1
            continue
        conclusion = run_info.get('conclusion')
        if conclusion == 'success':
            return True, 'CI passed'
        conclusions.append(str(conclusion))
    if unfinished > 0:
        return False, 'the CI run for HEAD has not finished'
    return False, 'CI did not pass for HEAD: ' + ', '.join(conclusions)


def pick_run_id(runs, commit):
    """Return the id of the newest run made for a commit, 0 when there is none.

    runs is the list "gh run list --json databaseId,headSha" prints, newest
    first.
    """
    for run_info in runs:
        if run_info.get('headSha') == commit:
            return run_info['databaseId']
    return 0


def read_at_head(path):
    """Return a tracked file as of HEAD, not as of the working tree."""
    return git('show', 'HEAD:' + path)


def on_stable(command):
    """Return a command that runs with the stable Rust of rustup.

    CI installs the latest stable Rust. An older distribution Rust earlier
    on PATH misses the clippy lints CI fails on.
    """
    argv = ['rustup', 'run', 'stable']
    argv.extend(command)
    return argv


def ci_checks():
    """Return the checks of the CI workflow except its test run."""
    checks = []
    checks.append(on_stable(['cargo', 'fmt', '--check']))
    checks.append(on_stable(['cargo', 'clippy', '--all-targets', '--',
                             '-D', 'warnings']))
    checks.append(on_stable(['cargo', 'clippy', '--all-targets',
                             '--features', CI_FEATURES, '--',
                             '-D', 'warnings']))
    checks.append(on_stable(['scripts/check-docs-tools.sh']))
    checks.append(on_stable(['cargo', 'audit']))
    checks.append(on_stable(['cargo', 'build', '--release']))
    return checks


def ci_test_command():
    """Return the test run of the CI workflow."""
    return on_stable(['cargo', 'test', '--features', CI_FEATURES, '--',
                      '--test-threads=1'])


def cargo_lock_command():
    """Return the command that makes Cargo.lock follow the Cargo.toml version."""
    return on_stable(['cargo', 'update', '-p', PACKAGE, '--offline'])


def wait_for_release_run(tag, commit):
    """Return the id of the Release workflow run the push of a tag started.

    The run is listed a few seconds after the push, so this asks until it
    appears or RUN_APPEARS_SECONDS pass.
    """
    deadline = time.monotonic() + RUN_APPEARS_SECONDS
    while True:
        runs = gh_json('run', 'list', '--workflow', RELEASE_WORKFLOW,
                       '--branch', tag, '--json', 'databaseId,headSha')
        run_id = pick_run_id(runs, commit)
        if run_id != 0:
            return run_id
        if time.monotonic() > deadline:
            fail('no %s workflow run for %s after %d seconds; are Actions '
                 'enabled on the fork?' % (RELEASE_WORKFLOW, tag,
                                           RUN_APPEARS_SECONDS))
        time.sleep(RUN_POLL_SECONDS)


def set_release_notes(tag, version):
    """Replace the generated release notes with the changelog section of a version."""
    notes = changelog_section(read_at_head('CHANGELOG.md'), version)
    # "with" removes the temporary directory when its block ends.
    with tempfile.TemporaryDirectory() as work_dir:
        notes_file = Path(work_dir) / 'notes.md'
        notes_file.write_text(notes)
        run(['gh', 'release', 'edit', tag, '--notes-file', str(notes_file)])


def check_release_assets(tag, version):
    """Fail, naming each file, when the release lacks a tarball, .deb or checksum."""
    release = gh_json('release', 'view', tag, '--json', 'assets')
    present = []
    for asset in release['assets']:
        present.append(asset['name'])
    missing = missing_assets(expected_assets(version), present)
    if len(missing) > 0:
        fail('release %s lacks: %s' % (tag, ', '.join(missing)))
    print('release %s has all %d expected files' % (tag, len(present)))


def prepare(args):
    """Check, build and test the tree, then write the release commit of a version."""
    version = args.version
    dry_run = args.dry_run
    tag = tag_name(version)
    require_valid_version(version)
    require_tools(['git', 'rustup', 'cargo-audit'])
    require_clean_worktree()

    if local_tag_commit(tag) != '':
        fail('tag %s exists locally' % tag)
    if remote_tag_commit(tag) != '':
        fail('tag %s exists on %s' % (tag, REMOTE))

    changelog_path = REPO_ROOT / 'CHANGELOG.md'
    changelog = changelog_path.read_text()
    if find_open_heading(changelog.split('\n')) < 0:
        fail('CHANGELOG.md has no open section to release')

    # Nothing is written before the checks of the CI workflow have passed.
    for check in ci_checks():
        act(dry_run, check)
    if args.skip_test:
        print('skipped: cargo test')
    else:
        act(dry_run, ci_test_command())

    cargo_toml_path = REPO_ROOT / 'Cargo.toml'
    announce(dry_run, 'set version = "%s" in Cargo.toml' % version)
    if not dry_run:
        text = cargo_toml_path.read_text()
        cargo_toml_path.write_text(set_version_in_cargo_toml(text, version))
    act(dry_run, cargo_lock_command())

    today = date.today().isoformat()
    heading = changelog_heading(version, today)
    announce(dry_run, 'rename the open CHANGELOG.md section to "%s"' % heading)
    if not dry_run:
        changelog_path.write_text(close_changelog(changelog, version, today))

    body = ('Set the version in Cargo.toml and Cargo.lock to %s and rename '
            'the open CHANGELOG.md section to %s.' % (version, version))
    act(dry_run, ['git', 'commit', '-a', '-m', 'Release ' + version,
                  '-m', body])

    print('')
    print('Next: push the commit, wait for CI, then publish:')
    print('    git push %s %s' % (REMOTE, RELEASE_BRANCH))
    print('    scripts/release.py publish')


def publish(args):
    """Tag the commit origin/main points at and check the GitHub release it builds."""
    dry_run = args.dry_run
    require_tools(['git', 'gh'])
    require_clean_worktree()

    version = version_in_cargo_toml(read_at_head('Cargo.toml'))
    tag = tag_name(version)
    head = git('rev-parse', 'HEAD')

    # ls-remote reads the branch on origin without moving origin/main in
    # the checkout, which a dry run must not do.
    main_commit = remote_branch_commit(RELEASE_BRANCH)
    if main_commit != head:
        fail('HEAD is %s but %s/%s is %s; push or pull first' %
             (head, REMOTE, RELEASE_BRANCH, main_commit))

    if args.skip_ci_check:
        print('skipped: CI check')
    else:
        runs = gh_json('run', 'list', '--workflow', CI_WORKFLOW,
                       '--commit', head, '--json', 'conclusion,status')
        passed, reason = ci_verdict(runs)
        if not passed:
            fail(reason + ' (--skip-ci-check bypasses this)')
        print(reason)

    decision = remote_tag_decision(remote_tag_commit(tag), head)
    if decision == TAG_CONFLICT:
        fail('tag %s exists on %s at another commit than HEAD' % (tag, REMOTE))

    if decision == TAG_CREATE:
        local_commit = local_tag_commit(tag)
        if local_commit == '':
            act(dry_run, ['git', 'tag', '-a', tag, '-m',
                          '%s %s' % (PACKAGE, version)])
        elif local_commit != head:
            fail('tag %s exists locally at another commit than HEAD' % tag)
        act(dry_run, ['git', 'push', REMOTE, tag])
    else:
        print('tag %s is on %s at HEAD already' % (tag, REMOTE))

    if dry_run:
        print('would do: wait for the %s run of %s with gh run watch '
              '--exit-status' % (RELEASE_WORKFLOW, tag))
        print('would do: gh release edit %s --notes-file <changelog '
              'section of %s>' % (tag, version))
        print('would do: check the release has %s' %
              ', '.join(expected_assets(version)))
        return

    run_id = wait_for_release_run(tag, head)
    run(['gh', 'run', 'watch', str(run_id), '--exit-status'])
    set_release_notes(tag, version)
    check_release_assets(tag, version)
    print('released ' + tag)


def parse_args(argv):
    """Return the parsed command line of the script."""
    parser = argparse.ArgumentParser(description='Release narsil-xref.')
    parser.add_argument('--dry-run', action='store_true',
                        help='show what would run and change nothing')
    subcommands = parser.add_subparsers(dest='command', required=True)

    prepare_parser = subcommands.add_parser(
        'prepare', help='build, test and write the release commit')
    prepare_parser.add_argument('version', help='for example 2.1.0')
    prepare_parser.add_argument('--skip-test', action='store_true',
                                help='leave out cargo test')
    prepare_parser.set_defaults(handler=prepare)

    publish_parser = subcommands.add_parser(
        'publish', help='tag origin/main and check the GitHub release')
    publish_parser.add_argument('--skip-ci-check', action='store_true',
                                help='do not require a passing CI run for HEAD')
    publish_parser.set_defaults(handler=publish)
    return parser.parse_args(argv)


def main(argv):
    """Run the subcommand the command line names."""
    args = parse_args(argv)
    args.handler(args)


if __name__ == '__main__':
    main(sys.argv[1:])
