package main

import rego.v1

# === E8 #8: DAILY BACKUP ===
# Strategy: Regular backups of important data
# Machine-testable: Check for backup-related resources in K8s manifests

# E8-BK-001: Check for Velero Schedule resources (standard K8s backup tool)
deny contains msg if {
	input.kind == "Schedule"
	msg := sprintf("E8-BK-001: Backup schedule found: %v — verify retention policy [ISM-1403] [E8: Daily Backup (ML1)] [Tier: L2]", [input.metadata.name])
}

# E8-BK-002: Check for VolumeSnapshot resources (PVC backups)
deny contains msg if {
	input.kind == "VolumeSnapshot"
	msg := sprintf("E8-BK-002: Volume snapshot found: %v — verify backup schedule covers this [ISM-1403] [E8: Daily Backup (ML1)] [Tier: L2]", [input.metadata.name])
}

# E8-BK-003: Check for VolumeSnapshotClass (backup infrastructure)
deny contains msg if {
	input.kind == "VolumeSnapshotClass"
	msg := sprintf("E8-BK-003: Volume snapshot class found: %v — backup infrastructure is configured [ISM-1403] [E8: Daily Backup (ML1)] [Tier: L2]", [input.metadata.name])
}

# E8-BK-004: Check for Velero BackupStorageLocation (backup destination configured)
deny contains msg if {
	input.kind == "BackupStorageLocation"
	msg := sprintf("E8-BK-004: Backup storage location found: %v — backup destination is configured [ISM-1403] [E8: Daily Backup (ML1)] [Tier: L2]", [input.metadata.name])
}

# E8-BK-005: Flag deployments with persistent volumes that lack backup indicators
deny contains msg if {
	input.kind == "Deployment"
	volume := input.spec.template.spec.volumes[_]
	volume.persistentVolumeClaim.claimName != ""
	not input.metadata.annotations
	msg := sprintf("E8-BK-005: Deployment %v uses PVC %v but has no backup annotations — ensure backup schedule covers this volume [ISM-1403] [E8: Daily Backup (ML2)] [Tier: L2]", [input.metadata.name, volume.persistentVolumeClaim.claimName])
}

# E8-BK-006: Flag StatefulSets with persistent storage but no backup annotations
deny contains msg if {
	input.kind == "StatefulSet"
	volume := input.spec.template.spec.volumes[_]
	volume.persistentVolumeClaim.claimName != ""
	not input.metadata.annotations
	msg := sprintf("E8-BK-006: StatefulSet %v uses PVC %v but has no backup annotations — ensure backup schedule covers this [ISM-1403] [E8: Daily Backup (ML2)] [Tier: L2]", [input.metadata.name, volume.persistentVolumeClaim.claimName])
}
