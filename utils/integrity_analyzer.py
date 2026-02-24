import hashlib

class IntegrityAnalyzer:
    """
    Verifies file integrity by comparing user-provided hash
    with computed file hash
    """

    SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256"]

    @staticmethod
    def calculate_hash(file_path, algorithm):
        """
        Calculate hash of file using selected algorithm
        """
        algorithm = algorithm.lower()

        if algorithm not in IntegrityAnalyzer.SUPPORTED_ALGORITHMS:
            raise ValueError("Unsupported hash algorithm")

        hash_func = hashlib.new(algorithm)

        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_func.update(chunk)

        return hash_func.hexdigest()

    @classmethod
    def verify_integrity(cls, file_path, user_hash, algorithm):
        """
        Compare user-provided hash with computed hash
        """

        computed_hash = cls.calculate_hash(file_path, algorithm)

        if computed_hash.lower() == user_hash.lower():
            return {
                "integrity_status": "SAFE",
                "message": "File integrity verified. Hashes match.",
                "computed_hash": computed_hash
            }
        else:
            return {
                "integrity_status": "TAMPERED",
                "message": "File integrity check failed. Hash mismatch detected.",
                "computed_hash": computed_hash
            }
