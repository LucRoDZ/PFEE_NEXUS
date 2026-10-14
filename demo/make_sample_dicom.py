"""Generate synthetic chest X-ray DICOM files that carry a fake patient identity.

The fake identity is what the de-identification and the storage tests look for.
No real patient data is used anywhere in the PoC.

    python demo/make_sample_dicom.py --out var/samples --count 3
"""
import argparse
from pathlib import Path

import numpy as np
from pydicom.dataset import FileDataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

CR_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.1"

FAKE_PATIENT = {
    "PatientName": "DOE^JANE",
    "PatientID": "IPP-4821-7733",
    "PatientBirthDate": "19840312",
    "PatientSex": "F",
    "InstitutionName": "Hopital Saint-Exemple",
    "ReferringPhysicianName": "MARTIN^PAUL",
    "AccessionNumber": "ACC-2026-000917",
}


def make(path: Path, patient: dict, seed: int, burned_in: bool = False, size: int = 512) -> Path:
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = CR_IMAGE_STORAGE
    meta.MediaStorageSOPInstanceUID = generate_uid()
    meta.TransferSyntaxUID = ExplicitVRLittleEndian

    ds = FileDataset(str(path), {}, file_meta=meta, preamble=b"\0" * 128)
    for key, value in patient.items():
        setattr(ds, key, value)
    ds.SOPClassUID = CR_IMAGE_STORAGE
    ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.Modality = "CR"
    ds.BodyPartExamined = "CHEST"
    ds.StudyDescription = "Chest X-ray PA (synthetic)"
    ds.BurnedInAnnotation = "YES" if burned_in else "NO"

    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:size, 0:size]
    lungs = np.exp(-(((x - size * 0.33) ** 2) / (2 * (size * 0.12) ** 2) + ((y - size * 0.5) ** 2) / (2 * (size * 0.25) ** 2)))
    lungs += np.exp(-(((x - size * 0.67) ** 2) / (2 * (size * 0.12) ** 2) + ((y - size * 0.5) ** 2) / (2 * (size * 0.25) ** 2)))
    image = 3000 - 1800 * lungs + rng.normal(0, 60, (size, size))
    pixels = np.clip(image, 0, 4095).astype(np.uint16)

    ds.Rows, ds.Columns = pixels.shape
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0
    ds.PixelData = pixels.tobytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    ds.save_as(path, enforce_file_format=True)
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="var/samples")
    parser.add_argument("--count", type=int, default=3)
    args = parser.parse_args()
    out = Path(args.out)
    for i in range(args.count):
        print(make(out / f"chest_{i + 1}.dcm", FAKE_PATIENT, seed=i))
    print(make(out / "chest_burned_in.dcm", FAKE_PATIENT, seed=99, burned_in=True))


if __name__ == "__main__":
    main()
