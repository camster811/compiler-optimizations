"""Pinned, unprivileged Ubuntu analysis environment; no inference dependencies change.

Bootstrap: python3 -m evaluation.analysis_environment --install
The package lock includes the complete apt-resolved additional dependency set. Existing
host dependencies and the Python ABI are recorded in the analysis receipt. Extracted
packages live under ignored .analysis-env/, never in system directories.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
PREFIX = ROOT / '.analysis-env'
LOCK = Path(__file__).with_name('analysis_environment.lock.json')
PACKAGES = ['r-base-core', 'r-cran-lme4', 'r-cran-jsonlite', 'r-cran-renv',
            'python3-numpy', 'python3-scipy', 'python3-matplotlib']


def resolve_lock():
    raw = subprocess.check_output(['apt-get', '--simulate', 'install', '--no-install-recommends', *PACKAGES], text=True)
    specs = dict(re.findall(r'^Inst (\S+) \((\S+)', raw, re.M))
    for name in PACKAGES:
        if name not in specs:
            specs[name] = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', name], text=True)
    entries = []
    for name, version in sorted(specs.items()):
        meta = subprocess.check_output(['apt-cache', 'show', name + '=' + version], text=True)
        fields = dict(line.split(': ', 1) for line in meta.split('\n\n')[0].splitlines() if ': ' in line and not line.startswith(' '))
        entries.append(dict(name=name, version=version, sha256=fields['SHA256'], filename=Path(fields['Filename']).name))
    LOCK.write_text(json.dumps(dict(platform='Ubuntu 26.04 amd64; Python 3.14', packages=entries), indent=2, sort_keys=True)+'\n')
    print('Package lock resolved; record validated runtime_versions before final analysis.')


def install():
    lock = json.loads(LOCK.read_text())
    archives = PREFIX / 'archives'
    archives.mkdir(parents=True, exist_ok=True)
    missing = [p['name']+'='+p['version'] for p in lock['packages']
               if not (archives / p['filename']).exists()]
    if missing:
        subprocess.run(['apt-get', 'download', *missing], cwd=archives, check=True)
    for p in lock['packages']:
        archive = archives / p['filename']
        # apt percent-escapes epoch colons in downloaded filenames.
        if not archive.exists():
            matches = list(archives.glob(p['name'] + '_*.deb'))
            if len(matches) != 1:
                raise ValueError('missing/ambiguous archive: '+p['name'])
            archive = matches[0]
        if hashlib.sha256(archive.read_bytes()).hexdigest() != p['sha256']:
            raise ValueError('package checksum mismatch: '+p['name'])
        subprocess.run(['dpkg-deb', '-x', str(archive), str(PREFIX)], check=True)
    # Debian postinst normally supplies Renviron and absolute configuration links.
    environ = PREFIX / 'etc/R/Renviron'
    environ.write_bytes((PREFIX / 'usr/lib/R/etc/Renviron.ucf').read_bytes())
    for path in PREFIX.rglob('*'):
        if path.is_symlink():
            target = os.readlink(path)
            local = PREFIX / target.lstrip('/')
            if target.startswith('/') and local.exists():
                path.unlink()
                path.symlink_to(os.path.relpath(local, path.parent))
    # Ubuntu's matplotlib patches get_data_path() to an absolute distribution path.
    mpl = PREFIX/'usr/lib/python3/dist-packages/matplotlib/__init__.py'
    mpl.write_text(mpl.read_text().replace('/usr/share/matplotlib/mpl-data',
                                         str(PREFIX/'usr/share/matplotlib/mpl-data')))
    print('Installed pinned analysis packages in', PREFIX)


def environment():
    env = os.environ.copy()
    if (PREFIX / 'usr/lib/R/bin/exec/R').exists():
        lib = PREFIX / 'usr/lib/x86_64-linux-gnu'
        env.update(R_HOME=str(PREFIX/'usr/lib/R'), R_SHARE_DIR=str(PREFIX/'usr/share/R/share'),
                   R_INCLUDE_DIR=str(PREFIX/'usr/share/R/include'), R_DOC_DIR=str(PREFIX/'usr/share/doc/R'),
                   R_LIBS_SITE=str(PREFIX/'usr/lib/R/site-library'),
                   LD_LIBRARY_PATH=':'.join(map(str, [PREFIX/'usr/lib/R/lib', lib, lib/'blas', lib/'lapack']))
                   + (':'+env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else ''),
                   PYTHONPATH=str(PREFIX/'usr/lib/python3/dist-packages')
                   + (':'+env['PYTHONPATH'] if env.get('PYTHONPATH') else ''))
    env.update(OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1', MKL_NUM_THREADS='1',
               MPLBACKEND='Agg', MPLCONFIGDIR=str(PREFIX/'matplotlib-cache'))
    if (PREFIX/'etc/matplotlibrc').exists():
        env['MATPLOTLIBRC'] = str(PREFIX/'etc/matplotlibrc')
    return env


def activate():
    """Re-exec before importing scientific extensions so shared libraries are visible."""
    env = environment()
    if not os.environ.get('PHASE_H_ENV_ACTIVE'):
        env['PHASE_H_ENV_ACTIVE'] = '1'
        os.execve(sys.executable, [sys.executable, *sys.argv], env)


def r_command():
    binary = PREFIX / 'usr/lib/R/bin/exec/R'
    return [str(binary), '--vanilla', '--slave'] if binary.exists() else ['Rscript', '--vanilla']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resolve-lock', action='store_true')
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--run', nargs=argparse.REMAINDER, help='run a command in the pinned environment')
    args = parser.parse_args()
    if args.resolve_lock:
        resolve_lock()
    if args.install:
        install()
    if args.run:
        sys.exit(subprocess.call(args.run, env=environment()))
