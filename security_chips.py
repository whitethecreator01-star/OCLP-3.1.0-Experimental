"""
security_chips.py: Security Chips (Hackintosh) detection and patching

Installs a kext shipped as a zip in payloads/Kexts/Misc/ into the root volume.
Shown in Post-Install Root Patching as "Miscellaneous: Security Chips"
"""

import os
import shutil
import subprocess
import zipfile

from pathlib import Path

from ..base import BaseHardware, HardwareVariant

from ...base import PatchType

from .....constants import Constants

from .....datasets import smbios_data


# Name of the zip inside payloads/Kexts/Misc (newest match is used)
ZIP_GLOB: str = "AppleT2-v*.zip"

# Where the zip is unpacked for root patching (must be readable by root)
STAGING_ROOT: Path = Path("/Users/Shared/.oclp_security_chips")

# Set True (or export OCLP_SECURITY_CHIPS=1) to treat any machine as a target
FORCE_PRESENT: bool = False


class SecurityChips(BaseHardware):

    def __init__(self, xnu_major, xnu_minor, os_build, global_constants: Constants) -> None:
        super().__init__(xnu_major, xnu_minor, os_build, global_constants)


    def _find_zip(self):
        """
        Locate payloads/Kexts/Misc/<ZIP_GLOB>
        """
        folders = []

        kexts_path = getattr(self._constants, "payload_kexts_path", None)
        if kexts_path:
            folders.append(Path(kexts_path) / "Misc")

        payload_path = getattr(self._constants, "payload_path", None)
        if payload_path:
            folders.append(Path(payload_path) / "Kexts" / "Misc")

        # Running from source: walk up from this file looking for payloads/
        for parent in Path(__file__).resolve().parents:
            folders.append(parent / "payloads" / "Kexts" / "Misc")

        for folder in folders:
            try:
                matches = sorted(folder.glob(ZIP_GLOB))
            except OSError:
                continue
            if matches:
                return matches[-1]
        return None


    def _is_hackintosh(self) -> bool:
        """
        Real Macs report 'Apple' as firmware vendor, Hackintoshes report their board's vendor
        """
        if FORCE_PRESENT is True or os.environ.get("OCLP_SECURITY_CHIPS") == "1":
            return True

        vendor = getattr(self._computer, "firmware_vendor", None)
        if isinstance(vendor, str) and vendor.strip():
            return vendor.strip() != "Apple"

        # Fallback: model unknown to OCLP means it is not a real Mac
        model = getattr(self._computer, "real_model", None)
        return model not in smbios_data.smbios_dictionary


    def _stage_kext(self, zip_path: Path):
        """
        Unpack the zip so root patching can source the kext from a folder

        Returns:
            tuple: (staging folder, kext name) or None
        """
        try:
            stage = STAGING_ROOT / zip_path.stem
            if stage.exists():
                shutil.rmtree(stage)
            extract_to = stage / "System" / "Library" / "Extensions"
            extract_to.mkdir(parents=True, exist_ok=True)

            ditto = Path("/usr/bin/ditto")
            if ditto.exists():
                result = subprocess.run([str(ditto), "-x", "-k", str(zip_path), str(extract_to)],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                if result.returncode != 0:
                    raise OSError(result.stdout.decode(errors="ignore"))
            else:
                with zipfile.ZipFile(zip_path) as z:
                    z.extractall(extract_to)

            kexts = sorted(p.name for p in extract_to.iterdir() if p.is_dir() and p.suffix == ".kext")
            if not kexts:
                return None
            return stage, kexts[0]
        except Exception:
            return None


    def name(self) -> str:
        """
        Display name for end users
        """
        return f"{self.hardware_variant()}: Security Chips"


    def present(self) -> bool:
        """
        Targeting Hackintoshes that ship the Security Chips kext zip
        """
        if self._find_zip() is None:
            return False
        return self._is_hackintosh()


    def native_os(self) -> bool:
        """
        Never native, macOS has no driver for this kext
        """
        return False


    def hardware_variant(self) -> HardwareVariant:
        """
        Type of hardware variant
        """
        return HardwareVariant.MISCELLANEOUS


    def patches(self) -> dict:
        """
        Patches for Security Chips
        """
        zip_path = self._find_zip()
        if zip_path is None:
            return {}

        staged = self._stage_kext(zip_path)
        if staged is None:
            return {}
        stage, kext_name = staged

        # A version string starting with "/" is used as an absolute source root by sys_patch.py
        return {
            "Security Chips": {
                PatchType.OVERWRITE_SYSTEM_VOLUME: {
                    "/System/Library/Extensions": {
                        kext_name: str(stage),
                    },
                },
            },
        }
