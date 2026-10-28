# SPDX-License-Identifier: MIT
import math
class EvidenceScore:
    @staticmethod
    def calculate(completion, assessment, time, interaction):
        values=[float(completion),float(assessment),float(time),float(interaction)]
        if any(not math.isfinite(v) or v < 0 or v > 1 for v in values):
            raise ValueError("Evidence indicators must be in [0, 1].")
        return sum(values)/4.0
