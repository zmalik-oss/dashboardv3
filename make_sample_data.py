"""Generate the synthetic sample splits in data/sample/ (NOT real BETH data)."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from triage.sample_data import write_sample  # noqa: E402

if __name__ == "__main__":
    n = write_sample(ROOT / "data" / "sample")
    print("wrote data/sample: train=%d val=%d test=%d rows" % n)
