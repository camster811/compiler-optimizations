"""Offline F3 regression against archived campaign evidence; no inference or scores."""
import contextlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from evaluation import check_final_acceptance as acceptance
from llm_analysis.common import file_hash, load


class FinalAcceptanceTests(unittest.TestCase):
    def test_f3_accepts_archived_campaign_without_live_server_log_or_offsets(self):
        root = acceptance.ROOT
        digest, archive_name = (root/'results/final-v1/archive.sha256').read_text().split()
        archive = root/archive_name
        self.assertEqual(file_hash(archive), digest)
        campaign_id = load(root/'results/final-v1/private/tables_manifest.json')['campaign_id']
        hidden = {root/'llm_analysis/output/server.log',
                  root/'results/final-v1/llm/pre_final_server_state/offsets.txt'}
        original_open = Path.open

        def offline_open(path, *args, **kwargs):
            if path.resolve() in hidden:
                raise FileNotFoundError(f'Live server evidence hidden for regression: {path}')
            return original_open(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            # Use only the committed release, not the ignored live campaign directory.
            with tarfile.open(archive) as release:
                members = [m for m in release.getmembers()
                           if m.name == campaign_id or m.name.startswith(campaign_id+'/')]
                self.assertTrue(members)
                release.extractall(destination, members=members, filter='data')
            output = destination/'acceptance.json'
            with patch.object(Path, 'open', new=offline_open), \
                 patch.object(sys, 'argv', ['check_final_acceptance.py', '--campaign',
                                           str(destination/campaign_id), '--output', str(output)]), \
                 contextlib.redirect_stdout(io.StringIO()), \
                 self.assertRaises(SystemExit) as result:
                acceptance.main()
            self.assertEqual(result.exception.code, 0)
            report = load(output)
            self.assertEqual(report['failed'], [])
            self.assertEqual(len(report['checks']), 39)
            self.assertTrue(all(c['passed'] for c in report['checks']))
            cross_check = report['server_log_cross_check']
            self.assertEqual(cross_check['server_inference_tasks'], 528)
            self.assertEqual(cross_check['completed_http_200_attempts'], 528)
            self.assertEqual(cross_check['source_path'], 'results/final-v1/llm/server_final_run.log')
            self.assertEqual(cross_check['source_sha256'], file_hash(root/cross_check['source_path']))


if __name__ == '__main__':
    unittest.main()
