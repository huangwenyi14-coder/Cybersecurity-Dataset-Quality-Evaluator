"""Run offline regression tests in a disposable directory, without dataset access."""
from pathlib import Path
import argparse, importlib, json, sys, tempfile, unittest, os
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--temp-dir',type=Path,help='Existing disk location for temporary test files')
    args=parser.parse_args()
    names=('test_input_pipeline','test_ai_pipeline','test_authenticity','test_authenticity_tc',
           'test_defense_input','test_adversarial','test_annotation_semantics','test_defense_semantics','test_release')
    with tempfile.TemporaryDirectory(prefix='cyberq-tests-',dir=str(args.temp_dir) if args.temp_dir else None) as folder:
        suite=unittest.TestSuite()
        for name in names:
            module=importlib.import_module(name)
            module.BASE=Path(folder)/name
            module.BASE.mkdir()
            if hasattr(module,'Tests') and hasattr(module.Tests,'out'):
                module.Tests.out=module.BASE/'output'
            suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
        import runtime_config
        # Tests must never consume the user's local API credentials/settings.
        clean_env={k:v for k,v in os.environ.items() if k not in runtime_config.NAMES}
        with patch.object(runtime_config,'ENV_FILE',Path(folder)/'absent.env'),patch.dict(os.environ,clean_env,clear=True):
            result=unittest.TextTestRunner(verbosity=2).run(suite)
        print(json.dumps({'passed':result.wasSuccessful(),'tests_run':result.testsRun,'network':'mocked or offline'}))
        return 0 if result.wasSuccessful() else 1

if __name__=='__main__':
    raise SystemExit(main())
