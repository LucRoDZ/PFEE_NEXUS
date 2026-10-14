"""De-identification of DICOM files at the hospital, before anything leaves.

Implements a subset of the DICOM PS3.15 Annex E Basic Application Level
Confidentiality Profile. The table linking real patient IDs to pseudonyms is
stored only at the hospital (mapping.sqlite) and never sent to HDG.

Files flagged with burned-in annotations are quarantined: the standard leaves
pixel cleaning out of its scope, so the PoC refuses them rather than guessing.
"""
import hashlib
import hmac
import sqlite3

import pydicom
from pydicom.uid import generate_uid

from ..common.config import service_dir

HOME = service_dir("hospital")
MAPPING_DB = HOME / "mapping.sqlite"
SECRET_PATH = HOME / "pseudonym.secret"

# Attributes removed or emptied (subset of the Basic Profile, actions X / Z / D).
REMOVE = [
    "PatientName", "PatientBirthDate", "PatientBirthTime", "PatientAddress", "PatientTelephoneNumbers",
    "OtherPatientIDs", "OtherPatientNames", "PatientMotherBirthName", "PatientAge", "PatientWeight",
    "PatientSize", "ReferringPhysicianName", "PerformingPhysicianName", "OperatorsName",
    "InstitutionName", "InstitutionAddress", "InstitutionalDepartmentName", "StationName",
    "AccessionNumber", "StudyID", "RequestingPhysician", "AdmittingDiagnosesDescription",
]
UID_ATTRIBUTES = ["StudyInstanceUID", "SeriesInstanceUID", "SOPInstanceUID", "FrameOfReferenceUID"]


class Quarantined(Exception):
    pass


def _secret() -> bytes:
    if not SECRET_PATH.exists():
        import os
        SECRET_PATH.write_bytes(os.urandom(32))
        SECRET_PATH.chmod(0o600)
    return SECRET_PATH.read_bytes()


def pseudonym(patient_id: str) -> str:
    digest = hmac.new(_secret(), patient_id.encode(), hashlib.sha256).hexdigest()
    return "P-" + digest[:16]


def remember(patient_id: str, pseudo: str) -> None:
    conn = sqlite3.connect(MAPPING_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS mapping (patient_id TEXT PRIMARY KEY, pseudonym TEXT NOT NULL)")
    conn.execute("INSERT OR IGNORE INTO mapping VALUES (?, ?)", (patient_id, pseudo))
    conn.commit()
    conn.close()


def deidentify(ds: pydicom.Dataset) -> tuple[pydicom.Dataset, str]:
    if str(getattr(ds, "BurnedInAnnotation", "NO")).upper() == "YES":
        raise Quarantined("burned-in annotation present: pixel data must be cleaned before upload")
    real_id = str(ds.PatientID)
    pseudo = pseudonym(real_id)
    remember(real_id, pseudo)

    for keyword in REMOVE:
        if keyword in ds:
            delattr(ds, keyword)
    ds.remove_private_tags()
    ds.PatientID = pseudo
    ds.PatientName = ""
    for keyword in UID_ATTRIBUTES:
        if keyword in ds:
            setattr(ds, keyword, generate_uid(entropy_srcs=[pseudo, str(getattr(ds, keyword))]))
    if "SOPInstanceUID" in ds and hasattr(ds, "file_meta"):
        ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    ds.PatientIdentityRemoved = "YES"
    ds.DeidentificationMethod = "PS3.15 Basic Profile subset (NEXUS gateway)"
    return ds, pseudo
