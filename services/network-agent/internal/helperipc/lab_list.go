package helperipc

import (
	"sort"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
)

// OpListLabs returns the helper's bookkeeping, not a fresh kernel check (that is VerifyLab).
const OpListLabs = "ListLabs"

func (l *LabLifecycle) snapshot() ([]LabInfo, error) {
	if l == nil {
		return nil, errLabUnavailable
	}

	if !l.mu.TryLock() {
		return nil, errLabBusy
	}
	defer l.mu.Unlock()

	if l.closed {
		return nil, errLabUnavailable
	}

	items := make([]LabInfo, 0, len(l.labs))
	for _, lab := range l.labs {
		items = append(items, lab)
	}

	sort.Slice(items, func(i, j int) bool { return items[i].ProfileID < items[j].ProfileID })

	return items, nil
}

func validLabListResponse(req Request, resp Response) bool {
	if req.Operation != OpListLabs || !resp.OK {
		return resp.Labs == nil
	}

	if len(resp.Labs) > maxManagedLabs {
		return false
	}

	profiles := make(map[string]bool)
	namespaces := make(map[string]bool)

	for _, lab := range resp.Labs {
		if !helperauth.ValidProfileID(lab.ProfileID) ||
			!helperauth.ValidLabNamespace(lab.Namespace) ||
			(lab.State != LabSealed && lab.State != LabFaulted) ||
			profiles[lab.ProfileID] ||
			namespaces[lab.Namespace] {
			return false
		}

		profiles[lab.ProfileID] = true
		namespaces[lab.Namespace] = true
	}

	return true
}
