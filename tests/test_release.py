"""Tests for scripts/release.py, run with: python3 -m pytest tests/test_release.py"""

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / 'scripts' / 'release.py'

# Loads the script as a module, because scripts/ is not a package.
spec = importlib.util.spec_from_file_location('release', SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

SAMPLE_CARGO_TOML = """\
[package]
name = "sample"
version = "2.0.0"
edition = "2021"

[dependencies]
other = { version = "9.9.9" }

[workspace.package]
version = "7.7.7"
"""

SAMPLE_CHANGELOG = """\
# Changelog

Intro text.

## [Unreleased]

### Changed

- Something new.

## [1.7.0] - 2026-05-12

### Added

- Something old.

## [1.6.0] - 2026-02-16

- Older.
"""


def test_cargo_toml_version_is_read_from_package_table_only():
    assert release.version_in_cargo_toml(SAMPLE_CARGO_TOML) == '2.0.0'


def test_cargo_toml_version_write_changes_only_the_package_line():
    updated = release.set_version_in_cargo_toml(SAMPLE_CARGO_TOML, '2.1.0-rc1')
    assert release.version_in_cargo_toml(updated) == '2.1.0-rc1'
    expected = SAMPLE_CARGO_TOML.replace('version = "2.0.0"',
                                         'version = "2.1.0-rc1"')
    assert updated == expected


def test_cargo_toml_without_package_version_fails(capsys):
    with pytest.raises(SystemExit):
        release.version_in_cargo_toml('[dependencies]\nversion = "1.0.0"\n')
    assert 'no version line' in capsys.readouterr().err


def test_close_changelog_renames_unreleased():
    closed = release.close_changelog(SAMPLE_CHANGELOG, '2.1.0', '2026-11-22')
    assert '## [2.1.0] - 2026-11-22\n' in closed
    assert '## [Unreleased]' not in closed
    assert '## [1.7.0] - 2026-05-12' in closed


def test_close_changelog_renames_an_open_section_with_another_title():
    text = SAMPLE_CHANGELOG.replace('[Unreleased]', '[Next]')
    closed = release.close_changelog(text, '2.1.0', '2026-11-22')
    assert '## [2.1.0] - 2026-11-22\n' in closed
    assert '[Next]' not in closed


def test_close_changelog_renames_an_open_section_named_by_version():
    text = SAMPLE_CHANGELOG.replace('[Unreleased]', '[2.1.0]')
    closed = release.close_changelog(text, '2.1.0', '2026-11-22')
    assert '## [2.1.0] - 2026-11-22\n' in closed
    assert closed.count('## [2.1.0]') == 1


def test_close_changelog_fails_when_the_first_heading_is_released(capsys):
    text = SAMPLE_CHANGELOG.replace('## [Unreleased]\n\n### Changed\n\n'
                                    '- Something new.\n\n', '')
    with pytest.raises(SystemExit):
        release.close_changelog(text, '2.1.0', '2026-11-22')
    assert 'no open section' in capsys.readouterr().err


def test_changelog_section_stops_at_the_next_heading():
    body = release.changelog_section(SAMPLE_CHANGELOG, '1.7.0')
    assert body == '### Added\n\n- Something old.\n'


def test_changelog_section_of_the_last_heading_runs_to_the_end():
    body = release.changelog_section(SAMPLE_CHANGELOG, '1.6.0')
    assert body == '- Older.\n'


def test_changelog_section_fails_when_absent_or_empty(capsys):
    with pytest.raises(SystemExit):
        release.changelog_section(SAMPLE_CHANGELOG, '3.0.0')
    assert 'no section for 3.0.0' in capsys.readouterr().err

    empty = '## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-01-01\n- x\n'
    with pytest.raises(SystemExit):
        release.changelog_section(empty, '1.0.0')
    assert 'is empty' in capsys.readouterr().err


def test_remote_tag_decision():
    assert release.remote_tag_decision('', 'aaa') == release.TAG_CREATE
    assert release.remote_tag_decision('aaa', 'aaa') == release.TAG_REUSE
    assert release.remote_tag_decision('bbb', 'aaa') == release.TAG_CONFLICT


def test_expected_assets_cover_both_architectures():
    names = release.expected_assets('2.1.0')
    assert names == [
        'narsil-xref-v2.1.0-linux-x86_64.tar.gz',
        'narsil-xref-v2.1.0-linux-x86_64.tar.gz.sha256',
        'narsil-xref_2.1.0-1_amd64.deb',
        'narsil-xref_2.1.0-1_amd64.deb.sha256',
        'narsil-xref-v2.1.0-linux-aarch64.tar.gz',
        'narsil-xref-v2.1.0-linux-aarch64.tar.gz.sha256',
        'narsil-xref_2.1.0-1_arm64.deb',
        'narsil-xref_2.1.0-1_arm64.deb.sha256',
    ]


def test_expected_assets_write_a_prerelease_with_a_tilde_in_the_deb():
    names = release.expected_assets('2.1.0-rc1')
    assert 'narsil-xref-v2.1.0-rc1-linux-x86_64.tar.gz' in names
    assert 'narsil-xref_2.1.0~rc1-1_amd64.deb' in names


def test_missing_assets_names_only_the_absent_files():
    expected = release.expected_assets('2.1.0')
    present = list(expected)
    present.remove('narsil-xref_2.1.0-1_arm64.deb.sha256')
    present.remove('narsil-xref-v2.1.0-linux-x86_64.tar.gz')
    assert release.missing_assets(expected, present) == [
        'narsil-xref-v2.1.0-linux-x86_64.tar.gz',
        'narsil-xref_2.1.0-1_arm64.deb.sha256',
    ]


def test_ci_verdict_cases():
    success = {'status': 'completed', 'conclusion': 'success'}
    failure = {'status': 'completed', 'conclusion': 'failure'}
    running = {'status': 'in_progress', 'conclusion': ''}

    passed, _ = release.ci_verdict([failure, success])
    assert passed

    passed, reason = release.ci_verdict([])
    assert not passed
    assert 'no CI run' in reason

    passed, reason = release.ci_verdict([running])
    assert not passed
    assert 'not finished' in reason

    passed, reason = release.ci_verdict([failure])
    assert not passed
    assert 'failure' in reason


def test_pick_run_id_matches_the_commit():
    runs = [{'databaseId': 30, 'headSha': 'bbb'},
            {'databaseId': 20, 'headSha': 'aaa'}]
    assert release.pick_run_id(runs, 'aaa') == 20
    assert release.pick_run_id(runs, 'ccc') == 0


def which_nothing(name):
    """Stand in for shutil.which() on a host with no program installed."""
    return None


def distro_rustc_output(argv):
    """Stand in for output() on a host whose PATH finds an older distro rustc."""
    if argv[0] == 'rustup':
        return 'rustc 1.100.0'
    return 'rustc 1.97.1'


def test_require_stable_rustc_stops_on_another_rustc(monkeypatch, capsys):
    monkeypatch.setattr(release, 'output', distro_rustc_output)
    with pytest.raises(SystemExit):
        release.require_stable_rustc()
    assert 'put ~/.cargo/bin first in PATH' in capsys.readouterr().err


def test_require_tools_names_every_missing_program(monkeypatch, capsys):
    monkeypatch.setattr(release.shutil, 'which', which_nothing)
    with pytest.raises(SystemExit):
        release.require_tools(['git', 'cargo', 'gh'])
    assert 'not installed: git, cargo, gh' in capsys.readouterr().err


def run_git(repo, *args):
    """Run git in a test repository and return its stdout."""
    done = subprocess.run(['git', *args], cwd=repo, check=True,
                          stdout=subprocess.PIPE, text=True)
    return done.stdout.strip()


@pytest.fixture
def release_repo(tmp_path, monkeypatch):
    """A clean repository with a bare origin, and stubs of the Rust tools and gh.

    The stubs append their command line to stub-calls.log in tmp_path, so a
    test can check that they were not run.
    """
    monkeypatch.setenv('GIT_AUTHOR_NAME', 'Test')
    monkeypatch.setenv('GIT_AUTHOR_EMAIL', 'test@example.com')
    monkeypatch.setenv('GIT_COMMITTER_NAME', 'Test')
    monkeypatch.setenv('GIT_COMMITTER_EMAIL', 'test@example.com')

    origin = tmp_path / 'origin.git'
    subprocess.run(['git', 'init', '-q', '--bare', str(origin)], check=True)
    repo = tmp_path / 'repo'
    subprocess.run(['git', 'init', '-q', '-b', 'main', str(repo)], check=True)
    (repo / 'Cargo.toml').write_text(SAMPLE_CARGO_TOML)
    (repo / 'CHANGELOG.md').write_text(SAMPLE_CHANGELOG)
    run_git(repo, 'add', '.')
    run_git(repo, 'commit', '-q', '-m', 'start')
    run_git(repo, 'remote', 'add', 'origin', str(origin))
    run_git(repo, 'push', '-q', 'origin', 'main')

    stub_dir = tmp_path / 'stubs'
    stub_dir.mkdir()
    log_file = tmp_path / 'stub-calls.log'
    for name in ['cargo', 'rustc', 'rustup', 'cargo-audit', 'gh']:
        stub = stub_dir / name
        stub.write_text('#!/bin/sh\necho "%s $@" >> "%s"\n' % (name, log_file))
        stub.chmod(0o755)
    monkeypatch.setenv('PATH', str(stub_dir) + os.pathsep + os.environ['PATH'])
    monkeypatch.setattr(release, 'REPO_ROOT', repo)
    return repo


def stub_calls(repo):
    """Return the command lines the stubs recorded."""
    log_file = repo.parent / 'stub-calls.log'
    if not log_file.exists():
        return ''
    return log_file.read_text()


def test_prepare_dry_run_shows_the_steps_and_changes_nothing(release_repo,
                                                             capsys):
    release.main(['--dry-run', 'prepare', '2.0.1'])
    shown = capsys.readouterr().out
    assert 'would run: cargo fmt --check' in shown
    assert 'would run: cargo clippy --all-targets -- -D warnings' in shown
    assert ('would run: cargo clippy --all-targets --features native -- '
            '-D warnings') in shown
    assert 'would run: scripts/check-docs-tools.sh' in shown
    assert 'would run: cargo audit' in shown
    assert ('would run: env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 '
            'cargo test --no-fail-fast --features native -- '
            '--test-threads=1') in shown
    assert 'git commit -a -m \'Release 2.0.1\'' in shown
    assert 'git push origin main' in shown
    # Only the read-only rustc check ran a stub.
    assert stub_calls(release_repo) == ('rustc --version\n'
                                        'rustup run stable rustc --version\n')
    assert (release_repo / 'Cargo.toml').read_text() == SAMPLE_CARGO_TOML
    assert (release_repo / 'CHANGELOG.md').read_text() == SAMPLE_CHANGELOG
    assert run_git(release_repo, 'status', '--porcelain') == ''


def test_prepare_stops_on_a_dirty_tree(release_repo, capsys):
    (release_repo / 'Cargo.toml').write_text(SAMPLE_CARGO_TOML + '\n# edit\n')
    with pytest.raises(SystemExit):
        release.main(['--dry-run', 'prepare', '2.0.1'])
    assert 'uncommitted changes' in capsys.readouterr().err
    assert stub_calls(release_repo) == ''


def test_prepare_stops_on_a_local_tag(release_repo, capsys):
    run_git(release_repo, 'tag', 'v2.0.1')
    with pytest.raises(SystemExit):
        release.main(['--dry-run', 'prepare', '2.0.1'])
    assert 'v2.0.1 exists locally' in capsys.readouterr().err
    assert stub_calls(release_repo) == ''


def test_prepare_stops_on_a_tag_only_origin_has(release_repo, capsys):
    run_git(release_repo, 'tag', 'v2.0.1')
    run_git(release_repo, 'push', '-q', 'origin', 'v2.0.1')
    run_git(release_repo, 'tag', '-d', 'v2.0.1')
    with pytest.raises(SystemExit):
        release.main(['--dry-run', 'prepare', '2.0.1'])
    assert 'v2.0.1 exists on origin' in capsys.readouterr().err
    assert stub_calls(release_repo) == ''


def test_prepare_stops_on_a_malformed_version(release_repo, capsys):
    with pytest.raises(SystemExit):
        release.main(['--dry-run', 'prepare', 'v2.0'])
    assert 'is not a version' in capsys.readouterr().err
